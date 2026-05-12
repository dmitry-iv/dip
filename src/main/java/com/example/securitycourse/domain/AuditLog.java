package com.example.securitycourse.domain;

import com.example.securitycourse.audit.AuditCategory;
import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    @Column(name = "ts", nullable = false)
    private Instant timestamp = Instant.now();

    @Column(name = "actor_user_id")
    private UUID actorUserId;

    @Column(name = "actor_username", length = 100)
    private String actorUsername;

    @Column(name = "actor_roles", length = 255)
    private String actorRoles;

    @Column(name = "action", nullable = false, length = 80)
    private String action;

    @Column(name = "result", nullable = false, length = 20)
    private String result;

    @Column(name = "entity_type", length = 80)
    private String entityType;

    @Column(name = "entity_id", length = 120)
    private String entityId;

    @Column(name = "ip", length = 64)
    private String ip;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "details")
    private String details;

    // ===== Расширенные поля =====

    @Column(name = "severity", nullable = false)
    private int severity = 1;

    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 30)
    private AuditCategory category = AuditCategory.AUTH;

    @Column(name = "correlation_id")
    private UUID correlationId;

    @Column(name = "country_code", length = 2)
    private String countryCode;

    // ===== Hash chain =====

    @Column(name = "prev_hash", length = 64)
    private String prevHash;

    @Column(name = "hash", length = 64)
    private String hash;

    /** Монотонный счётчик, заполняется БД (BIGSERIAL). */
    @Column(name = "seq", insertable = false, updatable = false)
    private Long seq;

    public AuditLog() {
    }

    // ============ Getters / Setters ============

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public UUID getActorUserId() { return actorUserId; }
    public void setActorUserId(UUID actorUserId) { this.actorUserId = actorUserId; }

    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String actorUsername) { this.actorUsername = actorUsername; }

    public String getActorRoles() { return actorRoles; }
    public void setActorRoles(String actorRoles) { this.actorRoles = actorRoles; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }

    public String getEntityType() { return entityType; }
    public void setEntityType(String entityType) { this.entityType = entityType; }

    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }

    public int getSeverity() { return severity; }
    public void setSeverity(int severity) { this.severity = severity; }

    public AuditCategory getCategory() { return category; }
    public void setCategory(AuditCategory category) { this.category = category; }

    public UUID getCorrelationId() { return correlationId; }
    public void setCorrelationId(UUID correlationId) { this.correlationId = correlationId; }

    public String getCountryCode() { return countryCode; }
    public void setCountryCode(String countryCode) { this.countryCode = countryCode; }

    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }

    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }

    public Long getSeq() { return seq; }
    public void setSeq(Long seq) { this.seq = seq; }
}