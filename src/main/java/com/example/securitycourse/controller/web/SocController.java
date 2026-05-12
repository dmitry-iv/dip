package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.IncidentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Контроллер SOC-панели для аналитиков (роли MANAGER, ADMIN).
 * Это основное рабочее место аналитика: очередь новых инцидентов слева,
 * собственные инциденты в работе справа, действия assign/resolve.
 */
@Controller
@RequestMapping("/soc")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class SocController {

    private static final Logger log = LoggerFactory.getLogger(SocController.class);

    private final IncidentService incidentService;

    public SocController(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    @GetMapping
    public String dashboard(Authentication authentication, Model model) {
        UUID analystId = extractUserId(authentication);

        try {
            IncidentService.AnalystStats stats = incidentService.analystStats(analystId);
            model.addAttribute("analystStats", stats);
        } catch (Exception e) {
            log.warn("Failed to load analyst stats: {}", e.getMessage());
        }

        try {
            model.addAttribute("queue", incidentService.queue());
        } catch (Exception e) {
            log.warn("Failed to load queue: {}", e.getMessage());
            model.addAttribute("queue", java.util.Collections.emptyList());
        }

        try {
            model.addAttribute("myIncidents", incidentService.myIncidents(analystId));
        } catch (Exception e) {
            log.warn("Failed to load my incidents: {}", e.getMessage());
            model.addAttribute("myIncidents", java.util.Collections.emptyList());
        }

        model.addAttribute("currentUsername", authentication.getName());
        return "soc/dashboard";
    }

    /** Взять инцидент в работу — assigned = current user, status = IN_PROGRESS. */
    @PostMapping("/incidents/{id}/assign")
    public String assignToMe(@PathVariable UUID id, Authentication authentication,
                             RedirectAttributes ra) {
        UUID analystId = extractUserId(authentication);
        try {
            incidentService.assignToMe(id, analystId);
            ra.addFlashAttribute("savedOk", "Инцидент взят в работу");
        } catch (Exception e) {
            log.error("Assign failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка: " + e.getMessage());
        }
        return "redirect:/soc";
    }

    /** Закрыть инцидент. */
    @PostMapping("/incidents/{id}/resolve")
    public String resolve(@PathVariable UUID id,
                          @RequestParam("resolution") String resolution,
                          @RequestParam(value = "notes", required = false) String notes,
                          RedirectAttributes ra) {
        try {
            Incident.Status status = Incident.Status.valueOf(resolution);
            incidentService.resolve(id, status, notes);
            ra.addFlashAttribute("savedOk", "Инцидент закрыт со статусом " + status);
        } catch (Exception e) {
            log.error("Resolve failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка: " + e.getMessage());
        }
        return "redirect:/soc";
    }

    private UUID extractUserId(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof AuthPrincipal ap) {
            return ap.getUserId();
        }
        throw new IllegalStateException("No authenticated user");
    }
}