package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.TwoFactorService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Веб-контроллер настройки 2FA через обычные HTML-формы (без JS).
 */
@Controller
@RequestMapping("/profile/2fa")
public class WebTwoFactorController {

    private static final Logger log = LoggerFactory.getLogger(WebTwoFactorController.class);

    private final TwoFactorService twoFactorService;
    private final UserRepository userRepository;

    public WebTwoFactorController(TwoFactorService twoFactorService, UserRepository userRepository) {
        this.twoFactorService = twoFactorService;
        this.userRepository = userRepository;
    }

    /** Шаг 1: показать страницу с QR-кодом и формой подтверждения. */
    @GetMapping("/setup")
    public String setupPage(Authentication authentication, Model model,
                            @org.springframework.web.bind.annotation.RequestParam(value = "force", required = false) String force) {
        AuthPrincipal principal = extractPrincipal(authentication);
        AppUser user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        if (user.isTotpEnabled()) {
            return "redirect:/profile";
        }

        TwoFactorService.SetupChallenge ch = twoFactorService.initiateSetup(user);
        model.addAttribute("secret", ch.secret());
        model.addAttribute("qrCodeDataUri", ch.qrCodeDataUri());
        model.addAttribute("username", user.getUsername());
        // Флаг "обязательная настройка 2FA" — для EXTERNAL пользователей
        boolean isMandatory = user.getSource() == AppUser.Source.EXTERNAL || "1".equals(force);
        model.addAttribute("mfaMandatory", isMandatory);
        return "twofa/setup";
    }

    /** Шаг 2: проверить код, активировать 2FA, показать backup-коды. */
    @PostMapping("/confirm")
    public String confirm(Authentication authentication,
                          @RequestParam("secret") String secret,
                          @RequestParam("code") String code,
                          HttpServletRequest http,
                          RedirectAttributes ra,
                          Model model) {
        AuthPrincipal principal = extractPrincipal(authentication);
        try {
            List<String> backupCodes = twoFactorService.confirmSetup(
                    principal.getUserId(), secret, code, http);
            model.addAttribute("backupCodes", backupCodes);
            return "twofa/backup-codes";
        } catch (IllegalArgumentException e) {
            log.warn("2FA confirm failed: {}", e.getMessage());
            ra.addFlashAttribute("setupError", "Неверный код. Попробуйте ещё раз.");
            return "redirect:/profile/2fa/setup";
        } catch (Exception e) {
            log.error("2FA confirm error", e);
            ra.addFlashAttribute("setupError", "Ошибка: " + e.getMessage());
            return "redirect:/profile/2fa/setup";
        }
    }

    /** Отключение 2FA. */
    @PostMapping("/disable")
    public String disable(Authentication authentication, HttpServletRequest http,
                          RedirectAttributes ra) {
        AuthPrincipal principal = extractPrincipal(authentication);
        try {
            twoFactorService.disable(principal.getUserId(), http);
            ra.addFlashAttribute("disabled", true);
        } catch (Exception e) {
            log.error("2FA disable failed", e);
            ra.addFlashAttribute("disableError", e.getMessage());
        }
        return "redirect:/profile";
    }

    private AuthPrincipal extractPrincipal(Authentication authentication) {
        if (authentication == null) {
            throw new IllegalStateException("No authentication");
        }
        Object p = authentication.getPrincipal();
        if (p instanceof AuthPrincipal ap) return ap;
        throw new IllegalStateException("Unsupported principal type: "
                + (p == null ? "null" : p.getClass().getName()));
    }
}