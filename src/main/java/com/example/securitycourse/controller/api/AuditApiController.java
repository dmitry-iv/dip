package com.example.securitycourse.controller.api;

import com.example.securitycourse.dto.AuditLogResponse;
import com.example.securitycourse.service.AuditQueryService;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/audit")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class AuditApiController {

    private final AuditQueryService auditQueryService;

    public AuditApiController(AuditQueryService auditQueryService) {
        this.auditQueryService = auditQueryService;
    }

    @GetMapping
    public Page<AuditLogResponse> search(
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Integer minSeverity,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return auditQueryService.search(actor, action, category, minSeverity, from, to, page, size);
    }
}