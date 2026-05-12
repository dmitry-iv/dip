package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.CorrelationRule;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Правило: повышение привилегий.
 * Условие: ROLES_CHANGED, в результате которого пользователь получил роль ADMIN.
 * MITRE ATT&CK: T1098 — Account Manipulation.
 */
@Component
public class PrivilegeEscalationRule implements CorrelationRule {

    @Override
    public String name() {
        return "PRIVILEGE_ESCALATION";
    }

    @Override
    public String description() {
        return "Назначение роли ADMIN — потенциальное повышение привилегий";
    }

    @Override
    public int severity() {
        return 5;
    }

    @Override
    public String mitreTechnique() {
        return "T1098";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.ROLES_CHANGED.name().equals(event.action())) {
            return Optional.empty();
        }
        String details = event.details();
        if (details == null || !details.toUpperCase().contains("ADMIN")) {
            return Optional.empty();
        }

        String desc = String.format(
                "Пользователю '%s' назначена роль ADMIN. Действие выполнил: %s. Подробности: %s",
                event.entityId(), event.actorUsername(), details);

        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(), desc,
                List.of(event.id())));
    }
}