package com.example.securitycourse.security;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Фильтр принудительной настройки 2FA для пользователей типа EXTERNAL.
 *
 * Если EXTERNAL-пользователь успешно вошёл по паролю, но у него ещё не включена 2FA,
 * фильтр перенаправляет любой запрос (кроме страницы настройки 2FA, выхода и статики)
 * на /profile/2fa/setup. Это защищает от ситуации когда подрядчик/аудитор работает
 * с системой без обязательного второго фактора.
 *
 * Закрывает требование политики ИБ: для привилегированных и внешних учётных записей
 */
@Component
public class MfaEnforcementFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(MfaEnforcementFilter.class);

    /** Пути, доступные EXTERNAL-пользователю даже без настроенной 2FA. */
    private static final Set<String> ALLOWED_PATHS_WITHOUT_2FA = Set.of(
            "/profile/2fa/setup",
            "/profile/2fa/confirm",
            "/profile/2fa/disable",
            "/logout",
            "/login",
            "/2fa/verify",
            "/2fa/cancel",
            "/error",
            "/403"
    );

    /** Префиксы которые разрешены без проверки (статика, иконки). */
    private static final String[] ALLOWED_PREFIXES = {
            "/css/", "/js/", "/images/", "/fonts/", "/webjars/", "/favicon"
    };

    private final UserRepository userRepository;

    public MfaEnforcementFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String uri = request.getRequestURI();

        // Пропускаем статику и другие безобидные пути
        for (String prefix : ALLOWED_PREFIXES) {
            if (uri.startsWith(prefix)) {
                chain.doFilter(request, response);
                return;
            }
        }
        if (ALLOWED_PATHS_WITHOUT_2FA.contains(uri)) {
            chain.doFilter(request, response);
            return;
        }

        // Только для API не нужно — у API свой контур безопасности
        if (uri.startsWith("/api/")) {
            chain.doFilter(request, response);
            return;
        }

        // Проверяем текущего пользователя
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || !(auth.getPrincipal() instanceof AuthPrincipal principal)) {
            chain.doFilter(request, response);
            return;
        }

        // Если EXTERNAL и 2FA не включена — отправляем на setup
        AppUser user = userRepository.findById(principal.getUserId()).orElse(null);
        if (user != null
                && user.getSource() == AppUser.Source.EXTERNAL
                && !user.isTotpEnabled()) {
            log.info("MFA enforcement: redirecting EXTERNAL user '{}' to 2FA setup (was trying {})",
                    user.getUsername(), uri);
            response.sendRedirect("/profile/2fa/setup?force=1");
            return;
        }

        chain.doFilter(request, response);
    }
}