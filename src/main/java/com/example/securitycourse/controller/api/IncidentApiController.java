package com.example.securitycourse.controller.api;

import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.dto.IncidentResponse;
import com.example.securitycourse.service.HashChainService;
import com.example.securitycourse.service.IncidentService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
public class IncidentApiController {

    private final IncidentService incidentService;
    private final HashChainService hashChainService;

    public IncidentApiController(IncidentService incidentService, HashChainService hashChainService) {
        this.incidentService = incidentService;
        this.hashChainService = hashChainService;
    }

    @GetMapping("/incidents")
    public List<IncidentResponse> list() {
        return incidentService.recent().stream().map(IncidentResponse::from).toList();
    }

    @GetMapping("/incidents/stats")
    public IncidentService.DashboardStats stats() {
        return incidentService.stats();
    }

    @PostMapping("/incidents/{id}/status")
    public IncidentResponse update(@PathVariable UUID id,
                                   @RequestBody Map<String, String> body) {
        Incident.Status status = Incident.Status.valueOf(body.get("status"));
        Incident updated = incidentService.updateStatus(id, status, body.get("notes"));
        return IncidentResponse.from(updated);
    }

    @GetMapping("/audit/integrity-check")
    public HashChainService.IntegrityCheckResult verifyAuditIntegrity() {
        return hashChainService.verifyChain();
    }
}