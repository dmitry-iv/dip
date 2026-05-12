package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.MyActivityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Контроллер личной активности — для рядовых сотрудников (роль USER).
 * Показывает только то, что относится к самому пользователю:
 * последние входы, инциденты с его учётной записью, статус 2FA.
 */
@Controller
@RequestMapping("/me")
public class MeController {

    private static final Logger log = LoggerFactory.getLogger(MeController.class);

    private final UserRepository userRepository;
    private final MyActivityService myActivityService;

    public MeController(UserRepository userRepository, MyActivityService myActivityService) {
        this.userRepository = userRepository;
        this.myActivityService = myActivityService;
    }

    @GetMapping
    public String myActivity(Authentication authentication, Model model) {
        if (!(authentication.getPrincipal() instanceof AuthPrincipal ap)) {
            return "redirect:/login";
        }

        AppUser user = userRepository.findById(ap.getUserId()).orElse(null);
        if (user == null) {
            return "redirect:/login";
        }
        model.addAttribute("user", user);

        try {
            MyActivityService.MyStats stats = myActivityService.myStats(user.getUsername());
            model.addAttribute("stats", stats);
        } catch (Exception e) {
            log.warn("Failed to load my stats: {}", e.getMessage());
        }

        try {
            model.addAttribute("recentLogins", myActivityService.myRecentLogins(user.getUsername()));
        } catch (Exception e) {
            log.warn("Failed to load recent logins: {}", e.getMessage());
            model.addAttribute("recentLogins", java.util.Collections.emptyList());
        }

        try {
            model.addAttribute("myIncidents", myActivityService.myIncidents(user.getUsername()));
        } catch (Exception e) {
            log.warn("Failed to load my incidents: {}", e.getMessage());
            model.addAttribute("myIncidents", java.util.Collections.emptyList());
        }

        return "me/activity";
    }
}