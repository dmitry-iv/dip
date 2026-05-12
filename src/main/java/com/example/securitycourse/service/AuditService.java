package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.security.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final HashChainService hashChainService;
    private final ApplicationEventPublisher publisher;

    public AuditService(AuditLogRepository auditLogRepository,
                        HashChainService hashChainService,
                        ApplicationEventPublisher publisher) {
        this.auditLogRepository = auditLogRepository;
        this.hashChainService = hashChainService;
        this.publisher = publisher;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditLog log(HttpServletRequest request,
                        UUID actorUserId, String actorUsername, String actorRoles,
                        AuditActions action, AuditResults result,
                        String entityType, String entityId, String details) {
        return logRaw(request, actorUserId, actorUsername, actorRoles,
                action.name(), action.getCategory(), action.getDefaultSeverity(),
                result.name(), entityType, entityId, details, null);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditLog log(HttpServletRequest request,
                        UUID actorUserId, String actorUsername, String actorRoles,
                        String action, String result,
                        String entityType, String entityId, String details) {
        AuditCategory cat;
        int sev;
        try {
            AuditActions a = AuditActions.valueOf(action);
            cat = a.getCategory();
            sev = a.getDefaultSeverity();
        } catch (IllegalArgumentException ex) {
            cat = AuditCategory.SYSTEM;
            sev = 1;
        }
        return logRaw(request, actorUserId, actorUsername, actorRoles,
                action, cat, sev, result, entityType, entityId, details, null);
    }

    public AuditLog logCurrent(HttpServletRequest request,
                               AuditActions action, AuditResults result,
                               String entityType, String entityId, String details) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UUID userId = null;
        String username = null;
        String roles = null;
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() != null) {
            username = auth.getName();
            roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));
            if (auth.getPrincipal() instanceof AuthPrincipal p) {
                userId = p.getUserId();
            }
        }
        return log(request, userId, username, roles, action, result, entityType, entityId, details);
    }

    public AuditLog logCurrent(HttpServletRequest request,
                               String action, String result,
                               String entityType, String entityId, String details) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UUID userId = null;
        String username = null;
        String roles = null;
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() != null) {
            username = auth.getName();
            roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));
            if (auth.getPrincipal() instanceof AuthPrincipal p) {
                userId = p.getUserId();
            }
        }
        return log(request, userId, username, roles, action, result, entityType, entityId, details);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditLog logWithCorrelation(HttpServletRequest request,
                                       AuditActions action, AuditResults result,
                                       String details, UUID correlationId) {
        return logRaw(request, null, "system", "ROLE_SYSTEM",
                action.name(), action.getCategory(), action.getDefaultSeverity(),
                result.name(), null, null, details, correlationId);
    }

    private AuditLog logRaw(HttpServletRequest request,
                            UUID actorUserId, String actorUsername, String actorRoles,
                            String action, AuditCategory category, int severity,
                            String result, String entityType, String entityId,
                            String details, UUID correlationId) {

        AuditLog entry = new AuditLog();


        entry.setActorUserId(actorUserId);
        entry.setActorUsername(actorUsername);
        entry.setActorRoles(actorRoles);
        entry.setAction(action);
        entry.setResult(result);
        entry.setCategory(category);
        entry.setSeverity(severity);
        entry.setEntityType(entityType);
        entry.setEntityId(entityId);
        entry.setDetails(details);
        entry.setCorrelationId(correlationId);

        if (request != null) {
            entry.setIp(extractIp(request));
            entry.setUserAgent(request.getHeader("User-Agent"));
        }

        // ШАГ 1: получаем lock и предыдущий хеш
        String prev = hashChainService.acquirePreviousHash();
        entry.setPrevHash(prev);

        // ШАГ 2: внутри lock'а получаем монотонный timestamp (строго больше предыдущего)
        entry.setTimestamp(hashChainService.nextMonotonicTimestamp());

        // ШАГ 3: вычисляем hash и сохраняем
        String content = hashChainService.canonicalize(entry);
        String hash = hashChainService.sha256Hex(prev + "|" + content);
        entry.setHash(hash);

        AuditLog saved = auditLogRepository.save(entry);
        auditLogRepository.flush();
        saved = auditLogRepository.findById(saved.getId()).orElse(saved);

        // ШАГ 4: обновляем сентинель
        hashChainService.updateChainState(hash);

        publisher.publishEvent(new AuditEventCreated(
                saved.getId(),
                saved.getTimestamp(),
                saved.getActorUserId(),
                saved.getActorUsername(),
                saved.getAction(),
                saved.getCategory(),
                saved.getSeverity(),
                saved.getResult(),
                saved.getEntityType(),
                saved.getEntityId(),
                saved.getIp(),
                saved.getUserAgent(),
                saved.getDetails()
        ));

        return saved;
    }

    private String extractIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}