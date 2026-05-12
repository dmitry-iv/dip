package com.example.securitycourse.audit;

import java.time.Instant;
import java.util.UUID;

/**
 * Событие, публикуемое после успешной записи в журнал аудита.
 * Прослушивается движком корреляции и сервисом немедленных алертов.
 */
public record AuditEventCreated(
        UUID id,
        Instant timestamp,
        UUID actorUserId,
        String actorUsername,
        String action,
        AuditCategory category,
        int severity,
        String result,
        String entityType,
        String entityId,
        String ip,
        String userAgent,
        String details
) {
}