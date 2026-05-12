package com.example.securitycourse.dto;

import com.example.securitycourse.domain.Incident;

import java.time.Instant;
import java.util.UUID;

public class IncidentResponse {

    private UUID id;
    private Instant createdAt;
    private String ruleName;
    private String ruleDescription;
    private int severity;
    private String status;
    private String affectedUser;
    private String sourceIp;
    private String description;
    private String mitreTechnique;
    private Instant resolvedAt;
    private String resolutionNotes;

    public static IncidentResponse from(Incident i) {
        IncidentResponse r = new IncidentResponse();
        r.id = i.getId();
        r.createdAt = i.getCreatedAt();
        r.ruleName = i.getRuleName();
        r.ruleDescription = i.getRuleDescription();
        r.severity = i.getSeverity();
        r.status = i.getStatus().name();
        r.affectedUser = i.getAffectedUser();
        r.sourceIp = i.getSourceIp();
        r.description = i.getDescription();
        r.mitreTechnique = i.getMitreTechnique();
        r.resolvedAt = i.getResolvedAt();
        r.resolutionNotes = i.getResolutionNotes();
        return r;
    }

    public UUID getId() { return id; }
    public Instant getCreatedAt() { return createdAt; }
    public String getRuleName() { return ruleName; }
    public String getRuleDescription() { return ruleDescription; }
    public int getSeverity() { return severity; }
    public String getStatus() { return status; }
    public String getAffectedUser() { return affectedUser; }
    public String getSourceIp() { return sourceIp; }
    public String getDescription() { return description; }
    public String getMitreTechnique() { return mitreTechnique; }
    public Instant getResolvedAt() { return resolvedAt; }
    public String getResolutionNotes() { return resolutionNotes; }
}