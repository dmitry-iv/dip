package com.example.securitycourse.domain;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "incidents")
public class Incident {

    public enum Status {
        /** Только что обнаружен корреляцией. */
        NEW,
        /** Аналитик подтвердил, нуждается в расследовании. */
        ACK,
        /** Расследование идёт. */
        IN_PROGRESS,
        /** Решён, причина установлена и устранена. */
        RESOLVED,
        /** Ложное срабатывание корреляции. */
        FALSE_POSITIVE
    }

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    @Column(name = "rule_name", nullable = false, length = 100)
    private String ruleName;

    @Column(name = "rule_description", length = 500)
    private String ruleDescription;

    @Column(name = "severity", nullable = false)
    private int severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private Status status = Status.NEW;

    @Column(name = "affected_user", length = 100)
    private String affectedUser;

    @Column(name = "source_ip", length = 100)
    private String sourceIp;

    @Column(name = "description", length = 2000)
    private String description;

    @Column(name = "mitre_technique", length = 50)
    private String mitreTechnique;

    @Column(name = "related_log_ids", length = 4000)
    private String relatedLogIds;

    /** UUID аналитика, который взял инцидент в работу. NULL = не назначен. */
    @Column(name = "assigned_user_id")
    private UUID assignedUserId;

    /** Когда был назначен ответственный. */
    @Column(name = "assigned_at")
    private Instant assignedAt;

    @Column(name = "resolution_notes", length = 2000)
    private String resolutionNotes;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }
    public String getRuleDescription() { return ruleDescription; }
    public void setRuleDescription(String ruleDescription) { this.ruleDescription = ruleDescription; }
    public int getSeverity() { return severity; }
    public void setSeverity(int severity) { this.severity = severity; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getAffectedUser() { return affectedUser; }
    public void setAffectedUser(String affectedUser) { this.affectedUser = affectedUser; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }
    public String getRelatedLogIds() { return relatedLogIds; }
    public void setRelatedLogIds(String relatedLogIds) { this.relatedLogIds = relatedLogIds; }
    public UUID getAssignedUserId() { return assignedUserId; }
    public void setAssignedUserId(UUID assignedUserId) { this.assignedUserId = assignedUserId; }
    public Instant getAssignedAt() { return assignedAt; }
    public void setAssignedAt(Instant assignedAt) { this.assignedAt = assignedAt; }
    public String getResolutionNotes() { return resolutionNotes; }
    public void setResolutionNotes(String resolutionNotes) { this.resolutionNotes = resolutionNotes; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }
}