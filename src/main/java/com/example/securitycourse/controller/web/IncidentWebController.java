package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.repository.IncidentRepository;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.IncidentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Controller
@RequestMapping("/incidents")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class IncidentWebController {

    private static final Logger log = LoggerFactory.getLogger(IncidentWebController.class);

    private final IncidentRepository incidentRepository;
    private final IncidentService incidentService;
    private final AuditLogRepository auditLogRepository;
    private final UserRepository userRepository;

    public IncidentWebController(IncidentRepository incidentRepository,
                                 IncidentService incidentService,
                                 AuditLogRepository auditLogRepository,
                                 UserRepository userRepository) {
        this.incidentRepository = incidentRepository;
        this.incidentService = incidentService;
        this.auditLogRepository = auditLogRepository;
        this.userRepository = userRepository;
    }

    @GetMapping
    public String list(Model model) {
        List<Incident> all = incidentRepository.findAll(
                org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC, "createdAt"));
        model.addAttribute("incidents", all);

        long openCount = incidentRepository.countByStatus(Incident.Status.NEW);
        long inProgressCount = incidentRepository.countByStatus(Incident.Status.IN_PROGRESS);
        long resolvedCount = incidentRepository.countByStatus(Incident.Status.RESOLVED);
        long falsePositiveCount = incidentRepository.countByStatus(Incident.Status.FALSE_POSITIVE);
        java.time.Instant since24h = java.time.Instant.now().minusSeconds(86400);
        long highSeverity24h = incidentRepository
                .countBySeverityGreaterThanEqualAndCreatedAtAfter(4, since24h);

        model.addAttribute("openCount", openCount);
        model.addAttribute("inProgressCount", inProgressCount);
        model.addAttribute("resolvedCount", resolvedCount);
        model.addAttribute("falsePositiveCount", falsePositiveCount);
        model.addAttribute("highSeverity24h", highSeverity24h);
        model.addAttribute("totalCount", all.size());

        return "incidents/list";
    }

    @GetMapping("/{id}")
    public String detail(@PathVariable UUID id, Model model) {
        Incident incident = incidentRepository.findById(id).orElse(null);
        if (incident == null) {
            return "redirect:/incidents";
        }
        model.addAttribute("incident", incident);

        // Кто назначен
        if (incident.getAssignedUserId() != null) {
            userRepository.findById(incident.getAssignedUserId())
                    .ifPresent(u -> model.addAttribute("assignedUser", u));
        }

        // Связанные события аудита
        List<UUID> ids = parseRelatedLogIds(incident.getRelatedLogIds());
        if (!ids.isEmpty()) {
            model.addAttribute("relatedLogs", auditLogRepository.findAllById(ids));
        } else {
            model.addAttribute("relatedLogs", java.util.Collections.emptyList());
        }

        // Список аналитиков для передачи (MANAGER или ADMIN)
        List<AppUser> analysts = userRepository.findAll().stream()
                .filter(u -> u.getRoles() != null && u.getRoles().stream()
                        .anyMatch(r -> "MANAGER".equals(r.getName()) || "ADMIN".equals(r.getName())))
                .toList();
        model.addAttribute("analysts", analysts);

        return "incidents/detail";
    }

    @PostMapping("/{id}/assign")
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
        return "redirect:/incidents/" + id;
    }

    @PostMapping("/{id}/transfer")
    public String transfer(@PathVariable UUID id,
                           @RequestParam("newAssigneeId") UUID newAssigneeId,
                           RedirectAttributes ra) {
        try {
            incidentService.transferTo(id, newAssigneeId);
            ra.addFlashAttribute("savedOk", "Инцидент передан другому аналитику");
        } catch (Exception e) {
            log.error("Transfer failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка: " + e.getMessage());
        }
        return "redirect:/incidents/" + id;
    }

    @PostMapping("/{id}/resolve")
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
        return "redirect:/incidents/" + id;
    }

    @PostMapping("/{id}/status")
    public String updateStatus(@PathVariable UUID id,
                               @RequestParam("status") String statusStr,
                               @RequestParam(value = "notes", required = false) String notes,
                               RedirectAttributes ra) {
        try {
            Incident.Status status = Incident.Status.valueOf(statusStr);
            incidentService.updateStatus(id, status, notes);
            ra.addFlashAttribute("savedOk", "Статус обновлён: " + status);
        } catch (Exception e) {
            log.error("Update status failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка: " + e.getMessage());
        }
        return "redirect:/incidents/" + id;
    }

    private UUID extractUserId(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof AuthPrincipal ap) {
            return ap.getUserId();
        }
        throw new IllegalStateException("No authenticated user");
    }

    private List<UUID> parseRelatedLogIds(String json) {
        List<UUID> result = new ArrayList<>();
        if (json == null || json.isBlank() || json.equals("[]")) return result;
        String inner = json.trim();
        if (inner.startsWith("[")) inner = inner.substring(1);
        if (inner.endsWith("]")) inner = inner.substring(0, inner.length() - 1);
        for (String part : inner.split(",")) {
            String s = part.trim().replaceAll("\"", "");
            if (s.isEmpty()) continue;
            try {
                result.add(UUID.fromString(s));
            } catch (IllegalArgumentException ignored) { }
        }
        return result;
    }
}