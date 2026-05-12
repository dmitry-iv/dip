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
 * Правило: подбор пароля.
 * Условие: N или больше LOGIN_FAILURE с одного IP за окно T минут.
 * MITRE ATT&amp;CK: T1110 — Brute Force.
 */
@Component
public class BruteForceRule implements CorrelationRule {

    @Value("${app.correlation.brute-force.threshold:5}")
    private int threshold;

    @Value("${app.correlation.brute-force.window-minutes:5}")
    private int windowMinutes;

    @Override
    public String name() {
        return "BRUTE_FORCE";
    }

    @Override
    public String description() {
        return "Подбор пароля: серия неудачных попыток входа с одного IP";
    }

    @Override
    public int severity() {
        return 5;
    }

    @Override
    public String mitreTechnique() {
        return "T1110";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.LOGIN_FAILURE.name().equals(event.action())) {
            return Optional.empty();
        }
        if (event.ip() == null || event.ip().isBlank()) {
            return Optional.empty();
        }

        Instant since = Instant.now().minus(Duration.ofMinutes(windowMinutes));
        long count = repo.countByIpAndActionAndTimestampAfter(
                event.ip(), AuditActions.LOGIN_FAILURE.name(), since);

        if (count < threshold) {
            return Optional.empty();
        }

        List<AuditLog> recent = repo.findRecentByIpAndAction(
                event.ip(), AuditActions.LOGIN_FAILURE.name(), since);
        List<UUID> ids = recent.stream().map(AuditLog::getId).collect(Collectors.toList());

        String desc = String.format(
                "Обнаружено %d неудачных попыток входа с IP %s за последние %d минут",
                count, event.ip(), windowMinutes);

        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(), desc, ids));
    }
}