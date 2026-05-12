package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.CorrelationRule;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Правило: credential stuffing.
 * Условие: с одного IP за окно T минут была попытка входа под N разными логинами.
 * Отличается от brute-force тем, что меняется не пароль, а логин — типичный признак
 * массового перебора по слитой базе.
 * MITRE ATT&amp;CK: T1110.004 — Credential Stuffing.
 */
@Component
public class CredentialStuffingRule implements CorrelationRule {

    @Value("${app.correlation.credential-stuffing.window-minutes:10}")
    private int windowMinutes;

    @Value("${app.correlation.credential-stuffing.distinct-users-threshold:5}")
    private int distinctUsersThreshold;

    @Override
    public String name() {
        return "CREDENTIAL_STUFFING";
    }

    @Override
    public String description() {
        return "Credential stuffing: с одного IP перебираются разные логины";
    }

    @Override
    public int severity() {
        return 5;
    }

    @Override
    public String mitreTechnique() {
        return "T1110.004";
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
        long distinctUsers = repo.countDistinctUsersByIpAndAction(
                event.ip(), AuditActions.LOGIN_FAILURE.name(), since);

        if (distinctUsers < distinctUsersThreshold) {
            return Optional.empty();
        }

        String desc = String.format(
                "С IP %s за %d минут зафиксированы попытки входа под %d разными логинами",
                event.ip(), windowMinutes, distinctUsers);

        return Optional.of(IncidentDraft.of(this, null, event.ip(), desc, List.of()));
    }
}