package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.CorrelationRule;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Правило: подозрительная активность с MFA.
 * Условие: 3+ неудачных проверок MFA-кода для одного пользователя за 5 минут.
 * Признак того, что злоумышленник имеет валидный пароль, но не имеет доступа ко второму фактору.
 * MITRE ATT&amp;CK: T1621 — Multi-Factor Authentication Request Generation.
 */
@Component
public class MfaFailureRule implements CorrelationRule {

    private static final int THRESHOLD = 3;
    private static final int WINDOW_MINUTES = 5;

    @Override
    public String name() {
        return "MFA_BYPASS_ATTEMPT";
    }

    @Override
    public String description() {
        return "Многократные неудачные попытки прохождения 2FA";
    }

    @Override
    public int severity() {
        return 5;
    }

    @Override
    public String mitreTechnique() {
        return "T1621";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.MFA_FAILURE.name().equals(event.action())) {
            return Optional.empty();
        }
        if (event.actorUsername() == null) {
            return Optional.empty();
        }

        Instant since = Instant.now().minus(Duration.ofMinutes(WINDOW_MINUTES));
        long count = repo.countByActorUsernameAndActionAndTimestampAfter(
                event.actorUsername(), AuditActions.MFA_FAILURE.name(), since);

        if (count < THRESHOLD) {
            return Optional.empty();
        }

        String desc = String.format(
                "Пользователь '%s' получил %d неудачных проверок 2FA за %d минут — возможна попытка обхода MFA " +
                "(пароль скомпрометирован, второй фактор недоступен злоумышленнику)",
                event.actorUsername(), count, WINDOW_MINUTES);

        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(), desc, List.of(event.id())));
    }
}