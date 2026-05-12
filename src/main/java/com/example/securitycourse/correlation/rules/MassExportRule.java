package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.CorrelationRule;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.domain.AuditLog;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Правило: массовый экспорт данных.
 * Условие: пользователь выполнил N или больше DATA_EXPORT за окно T минут.
 * Признак возможной утечки данных или работы скрипта.
 * MITRE ATT&amp;CK: T1567 — Exfiltration Over Web Service.
 */
@Component
public class MassExportRule implements CorrelationRule {

    @Value("${app.correlation.mass-export.threshold:10}")
    private int threshold;

    @Value("${app.correlation.mass-export.window-minutes:10}")
    private int windowMinutes;

    @Override
    public String name() {
        return "MASS_EXPORT";
    }

    @Override
    public String description() {
        return "Массовый экспорт данных одним пользователем за короткий промежуток";
    }

    @Override
    public int severity() {
        return 4;
    }

    @Override
    public String mitreTechnique() {
        return "T1567";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.DATA_EXPORT.name().equals(event.action())) {
            return Optional.empty();
        }
        if (event.actorUsername() == null) {
            return Optional.empty();
        }

        Instant since = Instant.now().minus(Duration.ofMinutes(windowMinutes));
        long count = repo.countByActorUsernameAndActionAndTimestampAfter(
                event.actorUsername(), AuditActions.DATA_EXPORT.name(), since);

        if (count < threshold) {
            return Optional.empty();
        }

        List<AuditLog> recent = repo.findRecentByUserAndAction(
                event.actorUsername(), AuditActions.DATA_EXPORT.name(), since);
        List<UUID> ids = recent.stream().map(AuditLog::getId).collect(Collectors.toList());

        String desc = String.format(
                "Пользователь '%s' выполнил %d операций экспорта за %d минут (потенциальная утечка)",
                event.actorUsername(), count, windowMinutes);

        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(), desc, ids));
    }
}