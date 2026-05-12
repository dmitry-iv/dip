package com.example.securitycourse.correlation;

import java.util.List;
import java.util.UUID;

/**
 * Черновик инцидента, создаваемый правилом корреляции.
 * Преобразуется в сущность Incident в IncidentService.
 */
public record IncidentDraft(
        String ruleName,
        String ruleDescription,
        int severity,
        String affectedUser,
        String sourceIp,
        String description,
        List<UUID> relatedLogIds,
        String mitreTechnique
) {
    public static IncidentDraft of(CorrelationRule rule,
                                   String user,
                                   String ip,
                                   String description,
                                   List<UUID> relatedLogIds) {
        return new IncidentDraft(
                rule.name(),
                rule.description(),
                rule.severity(),
                user,
                ip,
                description,
                relatedLogIds,
                rule.mitreTechnique()
        );
    }
}