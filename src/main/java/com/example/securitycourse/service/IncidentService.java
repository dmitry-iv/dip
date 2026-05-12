package com.example.securitycourse.service;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditResults;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Incident;
import com.example.securitycourse.repository.IncidentRepository;
import com.example.securitycourse.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class IncidentService {

    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    /** Окно дедупликации: тот же rule+user/IP в этом окне → не создаём новый инцидент. */
    private static final Duration DEDUP_WINDOW = Duration.ofMinutes(15);

    private final IncidentRepository incidentRepository;
    private final UserRepository userRepository;
    private final ApplicationEventPublisher publisher;
    private final AuditService auditService;

    public IncidentService(IncidentRepository incidentRepository,
                           UserRepository userRepository,
                           ApplicationEventPublisher publisher,
                           AuditService auditService) {
        this.incidentRepository = incidentRepository;
        this.userRepository = userRepository;
        this.publisher = publisher;
        this.auditService = auditService;
    }

    @Transactional
    public Incident createIncident(IncidentDraft draft) {
        // Дедупликация по user
        if (draft.affectedUser() != null) {
            Optional<Incident> existing = incidentRepository
                    .findFirstByRuleNameAndAffectedUserAndStatusOrderByCreatedAtDesc(
                            draft.ruleName(), draft.affectedUser(), Incident.Status.NEW);
            if (existing.isPresent() && isWithinDedup(existing.get())) {
                return existing.get();
            }
        }
        if (draft.sourceIp() != null) {
            Optional<Incident> existing = incidentRepository
                    .findFirstByRuleNameAndSourceIpAndStatusOrderByCreatedAtDesc(
                            draft.ruleName(), draft.sourceIp(), Incident.Status.NEW);
            if (existing.isPresent() && isWithinDedup(existing.get())) {
                return existing.get();
            }
        }

        Incident i = new Incident();
        i.setRuleName(draft.ruleName());
        i.setRuleDescription(draft.ruleDescription());
        i.setSeverity(draft.severity());
        i.setStatus(Incident.Status.NEW);
        i.setAffectedUser(draft.affectedUser());
        i.setSourceIp(draft.sourceIp());
        i.setDescription(draft.description());
        i.setMitreTechnique(draft.mitreTechnique());
        i.setRelatedLogIds(toJsonArray(draft.relatedLogIds()));

        Incident saved = incidentRepository.save(i);
        log.warn("INCIDENT CREATED [{}] severity={} user={} ip={} desc={}",
                saved.getRuleName(), saved.getSeverity(),
                saved.getAffectedUser(), saved.getSourceIp(), saved.getDescription());

        auditService.logWithCorrelation(null,
                mapToAction(draft.ruleName()),
                AuditResults.INFO,
                String.format("Incident '%s' created: %s", draft.ruleName(), draft.description()),
                saved.getId());

        publisher.publishEvent(new IncidentCreatedEvent(saved));
        return saved;
    }

    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    public List<Incident> recent() {
        return incidentRepository.findTop20ByOrderByCreatedAtDesc();
    }

    /**
     * Универсальное обновление статуса инцидента.
     * Фиксирует действие SOC-аналитика в журнале аудита.
     */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Incident updateStatus(UUID id, Incident.Status newStatus, String notes) {
        Incident i = incidentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Incident not found"));
        Incident.Status oldStatus = i.getStatus();
        i.setStatus(newStatus);
        if (newStatus == Incident.Status.RESOLVED || newStatus == Incident.Status.FALSE_POSITIVE) {
            i.setResolvedAt(Instant.now());
        }
        if (notes != null) {
            i.setResolutionNotes(notes);
        }
        Incident saved = incidentRepository.save(i);

        // Аудит действия аналитика
        auditService.logCurrent(null,
                AuditActions.INCIDENT_STATUS_CHANGED, AuditResults.SUCCESS,
                "Incident", id.toString(),
                String.format("Status changed %s → %s (rule=%s)", oldStatus, newStatus, i.getRuleName()));

        return saved;
    }

    /** Аналитик берёт инцидент себе → assigned + статус IN_PROGRESS. */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Incident assignToMe(UUID incidentId, UUID userId) {
        Incident i = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new IllegalArgumentException("Incident not found"));
        i.setAssignedUserId(userId);
        i.setAssignedAt(Instant.now());
        if (i.getStatus() == Incident.Status.NEW) {
            i.setStatus(Incident.Status.IN_PROGRESS);
        }
        AppUser actor = userRepository.findById(userId).orElse(null);
        String username = actor != null ? actor.getUsername() : "unknown";
        log.info("Incident {} assigned to user '{}'", incidentId, username);
        Incident saved = incidentRepository.save(i);

        // Аудит действия аналитика — попадает в hash-цепочку
        auditService.logCurrent(null,
                AuditActions.INCIDENT_ASSIGNED, AuditResults.SUCCESS,
                "Incident", incidentId.toString(),
                String.format("Incident assigned to analyst '%s' (rule=%s, severity=%d)",
                        username, i.getRuleName(), i.getSeverity()));

        return saved;
    }

    /** Передать инцидент другому аналитику. */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Incident transferTo(UUID incidentId, UUID newAssigneeId) {
        Incident i = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new IllegalArgumentException("Incident not found"));
        UUID oldAssignee = i.getAssignedUserId();
        i.setAssignedUserId(newAssigneeId);
        i.setAssignedAt(Instant.now());
        Incident saved = incidentRepository.save(i);

        String oldName = oldAssignee != null
                ? userRepository.findById(oldAssignee).map(AppUser::getUsername).orElse("unknown")
                : "none";
        String newName = userRepository.findById(newAssigneeId).map(AppUser::getUsername).orElse("unknown");

        auditService.logCurrent(null,
                AuditActions.INCIDENT_TRANSFERRED, AuditResults.SUCCESS,
                "Incident", incidentId.toString(),
                String.format("Incident transferred from '%s' to '%s' (rule=%s)",
                        oldName, newName, i.getRuleName()));

        return saved;
    }

    /** Закрыть инцидент с указанием решения. */
    @PreAuthorize("hasAnyRole('MANAGER','ADMIN')")
    @Transactional
    public Incident resolve(UUID incidentId, Incident.Status resolution, String notes) {
        if (resolution != Incident.Status.RESOLVED && resolution != Incident.Status.FALSE_POSITIVE) {
            throw new IllegalArgumentException("Resolution must be RESOLVED or FALSE_POSITIVE");
        }
        Incident i = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new IllegalArgumentException("Incident not found"));
        i.setStatus(resolution);
        i.setResolvedAt(Instant.now());
        i.setResolutionNotes(notes);
        Incident saved = incidentRepository.save(i);

        // Аудит: разные action в зависимости от резолюции
        AuditActions action = resolution == Incident.Status.FALSE_POSITIVE
                ? AuditActions.INCIDENT_FALSE_POSITIVE
                : AuditActions.INCIDENT_RESOLVED;
        String notesShort = notes == null || notes.isBlank() ? "(без комментария)"
                : (notes.length() > 100 ? notes.substring(0, 100) + "..." : notes);
        auditService.logCurrent(null,
                action, AuditResults.SUCCESS,
                "Incident", incidentId.toString(),
                String.format("Incident closed as %s (rule=%s, severity=%d). Notes: %s",
                        resolution, i.getRuleName(), i.getSeverity(), notesShort));

        return saved;
    }

    public DashboardStats stats() {
        long open = incidentRepository.countByStatus(Incident.Status.NEW);
        long inProgress = incidentRepository.countByStatus(Incident.Status.IN_PROGRESS);
        Instant since = Instant.now().minusSeconds(86400);
        long high24h = incidentRepository.countBySeverityGreaterThanEqualAndCreatedAtAfter(4, since);
        long total = incidentRepository.count();
        return new DashboardStats(open, inProgress, high24h, total);
    }

    /** Статистика для конкретного аналитика (используется на /soc). */
    public AnalystStats analystStats(UUID analystId) {
        long openQueue = incidentRepository.countByStatus(Incident.Status.NEW);
        long mineInProgress = incidentRepository.countByAssignedUserIdAndStatus(
                analystId, Incident.Status.IN_PROGRESS);
        Instant since = Instant.now().minusSeconds(86400);
        long resolvedToday = incidentRepository.countByAssignedUserIdAndStatusInAndResolvedAtAfter(
                analystId, List.of(Incident.Status.RESOLVED, Incident.Status.FALSE_POSITIVE), since);
        Instant since24h = Instant.now().minusSeconds(86400);
        long highSev24h = incidentRepository.countBySeverityGreaterThanEqualAndCreatedAtAfter(4, since24h);
        return new AnalystStats(openQueue, mineInProgress, resolvedToday, highSev24h);
    }

    public List<Incident> queue() {
        return incidentRepository.findTop50ByStatusOrderBySeverityDescCreatedAtDesc(Incident.Status.NEW);
    }

    public List<Incident> myIncidents(UUID analystId) {
        return incidentRepository.findByAssignedUserIdAndStatusInOrderByCreatedAtDesc(
                analystId,
                List.of(Incident.Status.IN_PROGRESS, Incident.Status.ACK));
    }

    private boolean isWithinDedup(Incident existing) {
        return existing.getCreatedAt().isAfter(Instant.now().minus(DEDUP_WINDOW));
    }

    private String toJsonArray(List<UUID> ids) {
        if (ids == null || ids.isEmpty()) return "[]";
        return ids.stream()
                .map(u -> "\"" + u.toString() + "\"")
                .collect(Collectors.joining(",", "[", "]"));
    }

    private AuditActions mapToAction(String ruleName) {
        return switch (ruleName) {
            case "BRUTE_FORCE" -> AuditActions.BRUTE_FORCE_DETECTED;
            case "CREDENTIAL_STUFFING" -> AuditActions.CREDENTIAL_STUFFING;
            default -> AuditActions.ANOMALOUS_BEHAVIOR;
        };
    }

    public record DashboardStats(long openIncidents, long inProgress, long highSeverityLast24h, long total) {}
    public record AnalystStats(long openQueue, long mineInProgress, long resolvedToday24h, long highSeverity24h) {}
    public record IncidentCreatedEvent(Incident incident) {}
}