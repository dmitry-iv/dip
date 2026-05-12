package com.example.securitycourse.correlation.rules;

import com.example.securitycourse.audit.AuditActions;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.correlation.CorrelationRule;
import com.example.securitycourse.correlation.IncidentDraft;
import com.example.securitycourse.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;

/**
 * Правило: вход в систему в нерабочее время.
 * Условие: успешный логин между app.correlation.off-hours.start и .end (по локальному времени сервера).
 * Срабатывает на средне-низкий уровень (severity=3), не блокирует пользователя.
 */
@Component
public class OffHoursLoginRule implements CorrelationRule {

    @Value("${app.correlation.off-hours.start:20}")
    private int offHoursStart; // включительно

    @Value("${app.correlation.off-hours.end:7}")
    private int offHoursEnd;   // не включительно

    @Override
    public String name() {
        return "OFF_HOURS_LOGIN";
    }

    @Override
    public String description() {
        return "Вход в систему в нерабочее время";
    }

    @Override
    public int severity() {
        return 3;
    }

    @Override
    public String mitreTechnique() {
        return "T1078";
    }

    @Override
    public Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository repo) {
        if (!AuditActions.LOGIN_SUCCESS.name().equals(event.action())) {
            return Optional.empty();
        }

        int hour = event.timestamp().atZone(ZoneId.systemDefault()).getHour();
        boolean isOffHours = (offHoursStart <= offHoursEnd)
                ? (hour >= offHoursStart && hour < offHoursEnd)
                : (hour >= offHoursStart || hour < offHoursEnd);

        if (!isOffHours) {
            return Optional.empty();
        }

        String desc = String.format(
                "Пользователь '%s' выполнил вход в %02d:00 (нерабочее время) с IP %s",
                event.actorUsername(),
                hour,
                event.ip());

        return Optional.of(IncidentDraft.of(this, event.actorUsername(), event.ip(), desc,
                List.of(event.id())));
    }
}