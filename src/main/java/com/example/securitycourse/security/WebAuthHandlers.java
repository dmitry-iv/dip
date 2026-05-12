package com.example.securitycourse.security;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.service.AuditService;
import com.example.securitycourse.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class WebAuthHandlers {

    private static final Logger log = LoggerFactory.getLogger(WebAuthHandlers.class);

    private final AuthService authService;
    private final AuditService auditService;
    private final UserRepository userRepository; // Добавляем для 2FA, но используем безопасно

    // Конструктор: userRepository можно сделать @Lazy или проверять null, если 2FA ещё не готов
    public WebAuthHandlers(AuthService authService, AuditService auditService, UserRepository userRepository) {
        this.authService = authService;
        this.auditService = auditService;
        this.userRepository = userRepository;
    }

    /**
     * Handler успешного логина.
     * - Вызывает бизнес-логику AuthService (счётчики, lastLoginAt и т.д.)
     * - Проверяет 2FA (если инфраструктура готова)
     * - Пишет аудит в ВАШЕМ формате
     */
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication auth) -> {
            String username = auth.getName();

            try {
                // 1) Бизнес-логика: сброс счётчиков, обновление lastLoginAt и т.д.
                authService.onSuccessfulLogin(username, request);
            } catch (Exception e) {
                log.warn("AuthService.onSuccessfulLogin failed for '{}': {}", username, e.getMessage());
            }

            // 2) Проверка 2FA — только если userRepository инъектирован и пользователь найден
            try {
                if (userRepository != null) {
                    AppUser user = userRepository.findByUsernameIgnoreCase(username).orElse(null);
                    
                    // Проверяем, включена ли 2FA (метод должен существовать в AppUser)
                    if (user != null && isTotpEnabledSafe(user)) {
                        log.info("User '{}' has 2FA enabled — redirecting to /2fa/verify", username);

                        HttpSession session = request.getSession(true);
                        session.setAttribute("pendingMfaUserId", user.getId()); // Используем строку вместо константы, если класс 2FA ещё не готов

                        // Сбрасываем контекст — аутентификация ещё не завершена
                        SecurityContextHolder.clearContext();
                        request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");

                        response.sendRedirect("/2fa/verify");
                        return; // Выходим, не пишем успешный логин в аудит — это произойдёт после ввода 2FA
                    }
                }
            } catch (NoClassDefFoundError | NoSuchMethodError e) {
                // 2FA-инфраструктура ещё не готова — просто игнорируем и продолжаем как обычно
                log.debug("2FA infrastructure not ready, skipping 2FA check: {}", e.getMessage());
            } catch (Exception e) {
                log.warn("2FA check failed for user '{}': {}", username, e.getMessage());
            }

            // 3) Стандартный успешный вход (2FA не включен или не настроен)
            try {
                // ВАЖНО: используем ВАШУ сигнатуру метода auditService.logCurrent!
                auditService.logCurrent(request,
                        AuditActions.LOGIN_SUCCESS, AuditResults.SUCCESS,
                        null, null, "Form login");
            } catch (Exception e) {
                log.warn("Audit logCurrent failed: {}", e.getMessage());
            }
            response.sendRedirect("/");
        };
    }

    /**
     * Handler неудачного логина.
     * - Вызывает AuthService.onFailedLogin для защиты от брутфорса
     * - Пишет аудит
     * - Корректно обрабатывает LockedException / DisabledException
     */
    public AuthenticationFailureHandler loginFailureHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException ex) -> {
            String login = request.getParameter("username");

            try {
                // Защита от брутфорса: инкремент счётчика неудачных попыток
                if (login != null && !login.isBlank()) {
                    authService.onFailedLogin(login);
                }
            } catch (Exception e) {
                log.warn("AuthService.onFailedLogin failed: {}", e.getMessage());
            }

            try {
                // Аудит(соответствует текущей сигнатуре AuditService)
                auditService.log(request, null, login, null,
                        AuditActions.LOGIN_FAILURE, AuditResults.FAIL,
                        null, null, ex.getMessage());
            } catch (Exception e) {
                log.warn("Audit log failed: {}", e.getMessage());
            }

            // Редирект с правильным кодом ошибки
            if (ex instanceof LockedException) {
                response.sendRedirect("/login?locked");
            } else if (ex instanceof DisabledException) {
                response.sendRedirect("/login?disabled");
            } else {
                response.sendRedirect("/login?error");
            }
        };
    }

    /**
     * Handler успешного логаута.
     * - Пишет аудит
     */
    public LogoutSuccessHandler logoutSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication auth) -> {
            if (auth != null) {
                try {
                    auditService.logCurrent(request,
                            AuditActions.LOGOUT, AuditResults.SUCCESS,
                            null, null, "Logout");
                } catch (Exception e) {
                    log.warn("Audit logout log failed: {}", e.getMessage());
                }
            }
            response.sendRedirect("/login?logout");
        };
    }

    /**
     * Handler отказа в доступе (403).
     * - Обязательно логируем событие для аудита безопасности!
     */
    public AccessDeniedHandler accessDeniedHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex) -> {
            try {
                auditService.logCurrent(request,
                        AuditActions.ACCESS_DENIED, AuditResults.FAIL,
                        null, null, request.getRequestURI());
            } catch (Exception e) {
                log.warn("Audit access denied log failed: {}", e.getMessage());
            }
            response.sendRedirect("/403");
        };
    }

    /**
     * Безопасная проверка isTotpEnabled() — не упадёт, если метод ещё не добавлен в AppUser.
     */
    private boolean isTotpEnabledSafe(AppUser user) {
        try {
            // Рефлексия: проверяем, есть ли метод isTotpEnabled() и вызываем его
            var method = user.getClass().getMethod("isTotpEnabled");
            return (Boolean) method.invoke(user);
        } catch (NoSuchMethodException e) {
            // Метода ещё нет — считаем, что 2FA выключен
            return false;
        } catch (Exception e) {
            log.debug("Could not check isTotpEnabled for user {}: {}", user.getUsername(), e.getMessage());
            return false;
        }
    }
}