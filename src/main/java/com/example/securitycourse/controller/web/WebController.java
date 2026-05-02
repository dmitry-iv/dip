package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class WebController {

    private final UserRepository userRepository;
    private final UserService userService;

    public WebController(UserRepository userRepository, UserService userService) {
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @GetMapping("/")
    public String home(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/profile")
    public String profile(Model model, Authentication authentication) {
        Object p = authentication.getPrincipal();
        if (!(p instanceof AuthPrincipal ap)) {
            return "redirect:/login";
        }

        AppUser user = userRepository.findById(ap.getUserId()).orElse(null);
        if (user == null) {
            return "redirect:/login";
        }

        model.addAttribute("user", user);
        if (!model.containsAttribute("passwordForm")) {
            model.addAttribute("passwordForm", new ChangePasswordForm());
        }
        return "profile";
    }

    @PostMapping("/profile/password")
    public String changePassword(
            @ModelAttribute("passwordForm") ChangePasswordForm form,
            BindingResult binding,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes ra
    ) {
        Object p = authentication.getPrincipal();
        if (!(p instanceof AuthPrincipal ap)) {
            return "redirect:/login";
        }

        if (isBlank(form.currentPassword)) {
            binding.rejectValue("currentPassword", "required", "Введите текущий пароль");
        }
        if (isBlank(form.newPassword)) {
            binding.rejectValue("newPassword", "required", "Введите новый пароль");
        }
        if (isBlank(form.confirmPassword)) {
            binding.rejectValue("confirmPassword", "required", "Подтвердите новый пароль");
        }
        if (!isBlank(form.newPassword) && !isBlank(form.confirmPassword) && !form.newPassword.equals(form.confirmPassword)) {
            binding.rejectValue("confirmPassword", "mismatch", "Пароли не совпадают");
        }

        if (binding.hasErrors()) {
            ra.addFlashAttribute("org.springframework.validation.BindingResult.passwordForm", binding);
            ra.addFlashAttribute("passwordForm", form);
            return "redirect:/profile";
        }

        try {
            userService.changePassword(ap.getUserId(), form.currentPassword, form.newPassword, request);
            ra.addFlashAttribute("passwordSuccess", "Пароль успешно изменён");
        } catch (IllegalArgumentException ex) {
            if ("CURRENT_PASSWORD_INVALID".equals(ex.getMessage())) {
                binding.rejectValue("currentPassword", "invalid", "Текущий пароль неверный");
            } else {
                binding.rejectValue("newPassword", "invalid", ex.getMessage());
            }
            ra.addFlashAttribute("org.springframework.validation.BindingResult.passwordForm", binding);
            ra.addFlashAttribute("passwordForm", form);
        }
        return "redirect:/profile";
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static class ChangePasswordForm {
        @NotBlank
        public String currentPassword;
        @NotBlank
        public String newPassword;
        @NotBlank
        public String confirmPassword;
    }

    @GetMapping("/report")
    public String report() {
        return "report";
    }

    @GetMapping("/403")
    public String forbidden() {
        return "error/403";
    }
}