package com.example.securitycourse.controller.web;

import com.example.securitycourse.service.AuditQueryService;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;

@Controller
@RequestMapping("/audit")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class AuditWebController {

    private final AuditQueryService auditQueryService;

    public AuditWebController(AuditQueryService auditQueryService) {
        this.auditQueryService = auditQueryService;
    }

    @GetMapping
    public String list(@RequestParam(required = false) String actor,
                       @RequestParam(required = false) String action,
                       @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                       @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
                       @RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "20") int size,
                       Model model) {

        Page<com.example.securitycourse.dto.AuditLogResponse> logs = auditQueryService.search(actor, action, from, to, page, size);
        model.addAttribute("logs", logs);
        model.addAttribute("actor", actor);
        model.addAttribute("action", action);
        model.addAttribute("from", from);
        model.addAttribute("to", to);
        return "audit/list";
    }
}
