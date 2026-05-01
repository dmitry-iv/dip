package com.example.securitycourse.service;

import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void log(HttpServletRequest request,
                    UUID actorUserId,
                    String actorUsername,
                    String actorRoles,
                    String action,
                    String result,
                    String entityType,
                    String entityId,
                    String details) {

        AuditLog log = new AuditLog();
        log.setTimestamp(Instant.now());
        log.setActorUserId(actorUserId);
        log.setActorUsername(actorUsername);
        log.setActorRoles(actorRoles);
        log.setAction(action);
        log.setResult(result);
        log.setEntityType(entityType);
        log.setEntityId(entityId);
        if (request != null) {
            log.setIp(extractIp(request));
            log.setUserAgent(request.getHeader("User-Agent"));
        }
        log.setDetails(details);

        auditLogRepository.save(log);
    }

    public void logCurrent(HttpServletRequest request,
                           String action,
                           String result,
                           String entityType,
                           String entityId,
                           String details) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UUID userId = null;
        String username = null;
        String roles = null;
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() != null) {
            username = auth.getName();
            roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
            Object principal = auth.getPrincipal();
            if (principal instanceof com.example.securitycourse.security.AuthPrincipal p) {
                userId = p.getUserId();
            }
        }
        log(request, userId, username, roles, action, result, entityType, entityId, details);
    }

    private String extractIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
