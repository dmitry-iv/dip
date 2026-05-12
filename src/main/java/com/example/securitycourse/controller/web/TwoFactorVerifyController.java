package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
// import com.example.securitycourse.security.AuthPrincipal; // <-- УДАЛИТЕ, если класс не существует
import com.example.securitycourse.security.CustomUserDetailsService;
import com.example.securitycourse.service.TwoFactorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

@Controller
@RequestMapping("/2fa")
public class TwoFactorVerifyController {

    private static final Logger log = LoggerFactory.getLogger(TwoFactorVerifyController.class);

    // Используем то же имя константы, что и в безопасном примере WebAuthHandlers
    public static final String SESSION_PENDING_USER_ID = "pendingMfaUserId";

    private final UserRepository userRepository;
    private final TwoFactorService twoFactorService;
    private final CustomUserDetailsService userDetailsService;
    
    // HttpSessionSecurityContextRepository работает в Spring Security 6, но требует аккуратности
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    public TwoFactorVerifyController(UserRepository userRepository,
                                     TwoFactorService twoFactorService,
                                     CustomUserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.twoFactorService = twoFactorService;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/verify")
    public String verifyPage(HttpSession session, Model model) {
        // 1. Получаем ID из сессии
        UUID pendingId = (UUID) session.getAttribute(SESSION_PENDING_USER_ID);
        
        // 2. Валидация: если нет ID в сессии — отправляем на логин
        if (pendingId == null) {
            log.debug("No pending user ID in session, redirecting to login");
            return "redirect:/login";
        }

        // 3. Ищем пользователя в БД
        AppUser user = userRepository.findById(pendingId).orElse(null);
        if (user == null) {
            log.warn("Pending user {} not found in DB, cleaning session", pendingId);
            session.removeAttribute(SESSION_PENDING_USER_ID);
            return "redirect:/login?error";
        }

        model.addAttribute("username", user.getUsername());
        return "twofa/verify";
    }

    @PostMapping("/verify")
    public String verifyCode(@RequestParam("code") String code,
                             HttpSession session,
                             HttpServletRequest request,
                             HttpServletResponse response,
                             RedirectAttributes ra) {
        
        UUID pendingId = (UUID) session.getAttribute(SESSION_PENDING_USER_ID);
        if (pendingId == null) {
            return "redirect:/login";
        }

        AppUser user = userRepository.findById(pendingId).orElse(null);
        if (user == null) {
            session.removeAttribute(SESSION_PENDING_USER_ID);
            return "redirect:/login?error";
        }

        // Проверка кода
        boolean ok;
        try {
            // ВАЖНО: Убедитесь, что сигнатура метода в TwoFactorService совпадает!
            // Если метод принимает только (user, code), уберите 'request' отсюда.
            ok = twoFactorService.verify(user, code, request);
        } catch (Exception e) {
            log.error("2FA verify error", e);
            ok = false;
        }

        if (!ok) {
            log.warn("2FA verify FAILED for user '{}'", user.getUsername());
            return "redirect:/2fa/verify?error";
        }

        // === УСПЕХ: Завершаем аутентификацию ===
        
        // 1. Чистим временный атрибут
        session.removeAttribute(SESSION_PENDING_USER_ID);

        // 2. Загружаем полные данные пользователя (с ролями)
        UserDetails fullUserDetails = userDetailsService.loadUserByUsername(user.getUsername());
        
        // 3. Создаём объект аутентификации
        Authentication newAuth = new UsernamePasswordAuthenticationToken(
                fullUserDetails,
                null, // пароль не храним
                fullUserDetails.getAuthorities()
        );

        // 4. Сохраняем в контекст безопасности
        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(newAuth);
        SecurityContextHolder.setContext(newContext);
        
        // 5. Сохраняем в сессию (чтобы работало на следующих запросах)
        try {
            securityContextRepository.saveContext(newContext, request, response);
        } catch (Exception e) {
            log.warn("Failed to save security context to session: {}", e.getMessage());
            // Фолбэк: сохраняем вручную, если репозиторий не сработал
            request.getSession().setAttribute(
                    "SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
        }

        log.info("2FA verified for user '{}', session upgraded", user.getUsername());
        return "redirect:/";
    }
}