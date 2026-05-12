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
 * Правило: попытка модификации журнала аудита.
 * Срабатывает на событие AUDIT_INTEGRITY_VIOLATION (его пишет HashChainService.verifyChain
 * при обнаружении разрыва цепочки).
 * MITRE ATT&amp;CK: T1070 — Indicator Removal on Host.
 */
@Component
public class AuditTamperingRule implements CorrelationRule {

    @Override
    public String name() {
        return "AUDIT_TAMPERING";
    }

    @Override
    public String description() {
        return "Обнаружено нарушение целостности журнала аудита (разрыв hash-цепочки)";
    }

    @Override
    public int severity() {
        return 5;
    }

    @Override
    public String mitreTechnique() {
        return "T1070";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.AUDIT_INTEGRITY_VIOLATION.name().equals(event.action())) {
            return Optional.empty();
        }
        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(),
                "Hash-цепочка журнала аудита нарушена. " + event.details(),
                List.of(event.id())));
    }
}