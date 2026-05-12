package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.dto.AuditLogResponse;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuditQueryService {

    private final AuditLogRepository auditLogRepository;

    public AuditQueryService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public Page<AuditLogResponse> search(String actor, String action,
                                         String category, Integer minSeverity,
                                         Instant from, Instant to,
                                         int page, int size) {

        Specification<AuditLog> spec = (root, q, cb) -> cb.conjunction();

        if (actor != null && !actor.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.like(cb.lower(root.get("actorUsername")),
                    "%" + actor.toLowerCase() + "%"));
        }
        if (action != null && !action.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("action"), action));
        }
        if (category != null && !category.isBlank()) {
            AuditCategory cat = AuditCategory.valueOf(category);
            spec = spec.and((root, q, cb) -> cb.equal(root.get("category"), cat));
        }
        if (minSeverity != null) {
            spec = spec.and((root, q, cb) -> cb.greaterThanOrEqualTo(root.get("severity"), minSeverity));
        }
        if (from != null) {
            spec = spec.and((root, q, cb) -> cb.greaterThanOrEqualTo(root.get("timestamp"), from));
        }
        if (to != null) {
            spec = spec.and((root, q, cb) -> cb.lessThanOrEqualTo(root.get("timestamp"), to));
        }

        Page<AuditLog> p = auditLogRepository.findAll(spec,
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "timestamp")));
        return p.map(this::toDto);
    }

    private AuditLogResponse toDto(AuditLog l) {
        AuditLogResponse dto = new AuditLogResponse();
        dto.setId(l.getId());
        dto.setTimestamp(l.getTimestamp());
        dto.setActorUserId(l.getActorUserId());
        dto.setActorUsername(l.getActorUsername());
        dto.setActorRoles(l.getActorRoles());
        dto.setAction(l.getAction());
        dto.setResult(l.getResult());
        dto.setEntityType(l.getEntityType());
        dto.setEntityId(l.getEntityId());
        dto.setIp(l.getIp());
        dto.setUserAgent(l.getUserAgent());
        dto.setDetails(l.getDetails());
        dto.setSeverity(l.getSeverity());
        dto.setCategory(l.getCategory() == null ? null : l.getCategory().name());
        dto.setCorrelationId(l.getCorrelationId());
        dto.setHash(l.getHash());
        return dto;
    }
}