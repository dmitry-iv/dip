package com.example.securitycourse.correlation;

import com.example.securitycourse.audit.AuditCategory;
import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.repository.AuditLogRepository;
import com.example.securitycourse.service.IncidentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Движок корреляции событий.
 *
 * Подписан на {@link AuditEventCreated} (публикуется AuditService после
 * фиксации записи в БД). Прогоняет событие через все зарегистрированные
 * правила {@link CorrelationRule} и при срабатывании создаёт инцидент.
 *
 * Работа асинхронная — не блокирует основной поток обработки запроса.
 */
@Component
public class CorrelationEngine {

    private static final Logger log = LoggerFactory.getLogger(CorrelationEngine.class);

    private final List<CorrelationRule> rules;
    private final AuditLogRepository auditLogRepository;
    private final IncidentService incidentService;

    @Value("${app.correlation.enabled:true}")
    private boolean enabled;

    public CorrelationEngine(List<CorrelationRule> rules,
                             AuditLogRepository auditLogRepository,
                             IncidentService incidentService) {
        this.rules = rules;
        this.auditLogRepository = auditLogRepository;
        this.incidentService = incidentService;
        log.info("Correlation engine initialized with {} rules: {}",
                rules.size(),
                rules.stream().map(CorrelationRule::name).toList());
    }

    @EventListener
    @Async("correlationExecutor")
    public void onAuditEvent(AuditEventCreated event) {
        if (!enabled) return;

        // Не пропускаем сами инциденты в корреляцию (чтобы не зациклиться)
        if (event.category() == AuditCategory.INCIDENT) {
            return;
        }

        for (CorrelationRule rule : rules) {
            try {
                rule.evaluate(event, auditLogRepository).ifPresent(draft -> {
                    log.info("Rule '{}' fired for event {}: {}", rule.name(), event.id(), draft.description());
                    incidentService.createIncident(draft);
                });
            } catch (Exception ex) {
                log.error("Correlation rule '{}' failed: {}", rule.name(), ex.getMessage(), ex);
            }
        }
    }
}