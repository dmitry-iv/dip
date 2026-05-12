package com.example.securitycourse.dto;

import java.time.Instant;
import java.util.UUID;

public class AuditLogResponse {

    private UUID id;
    private Instant timestamp;
    private UUID actorUserId;
    private String actorUsername;
    private String actorRoles;
    private String action;
    private String result;
    private String entityType;
    private String entityId;
    private String ip;
    private String userAgent;
    private String details;

    private int severity;
    private String category;
    private UUID correlationId;
    private String hash;

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
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public UUID getCorrelationId() { return correlationId; }
    public void setCorrelationId(UUID correlationId) { this.correlationId = correlationId; }
    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }
}