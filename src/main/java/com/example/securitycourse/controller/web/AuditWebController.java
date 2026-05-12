package com.example.securitycourse.controller.web;

import com.example.securitycourse.dto.AuditLogResponse;
import com.example.securitycourse.service.AuditQueryService;
import com.example.securitycourse.service.HashChainService;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@Controller
@RequestMapping("/audit")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class AuditWebController {

    private final AuditQueryService auditQueryService;
    private final HashChainService hashChainService;

    public AuditWebController(AuditQueryService auditQueryService, HashChainService hashChainService) {
        this.auditQueryService = auditQueryService;
        this.hashChainService = hashChainService;
    }

    @GetMapping
    public String list(@RequestParam(required = false) String actor,
                       @RequestParam(required = false) String action,
                       @RequestParam(required = false) String category,
                       @RequestParam(required = false) Integer minSeverity,
                       @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                       @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
                       @RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "50") int size,
                       Model model) {
        Page<AuditLogResponse> p = auditQueryService.search(actor, action, category, minSeverity, from, to, page, size);
        model.addAttribute("entries", p);
        model.addAttribute("actor", actor);
        model.addAttribute("action", action);
        model.addAttribute("category", category);
        model.addAttribute("minSeverity", minSeverity);
        return "audit/list";
    }

    /**
     * JSON-эндпоинт для проверки целостности из web-сессии.
     * Используется кнопкой "Проверить целостность" на странице /audit
     * (fetch с теми же cookie, что и текущий пользователь).
     */
    @GetMapping("/integrity-check")
    @ResponseBody
    public HashChainService.IntegrityCheckResult verifyIntegrity() {
        return hashChainService.verifyChain();
    }
}