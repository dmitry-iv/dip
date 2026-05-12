package com.example.securitycourse.correlation;

import com.example.securitycourse.audit.AuditEventCreated;
import com.example.securitycourse.repository.AuditLogRepository;

import java.util.Optional;

/**
 * Правило корреляции событий.
 *
 * Каждое правило получает только что записанное событие аудита и имеет
 * доступ к репозиторию журнала для запросов в скользящем окне.
 * Если условие выполнено — возвращает черновик инцидента.
 */
public interface CorrelationRule {

    /** Уникальное имя правила (для журнала и дедупликации инцидентов). */
    String name();

    /** Идентификатор техники MITRE ATT&CK (опционально). */
    default String mitreTechnique() {
        return null;
    }

    /** Описание для сообщений и UI. */
    String description();

    /** Базовый уровень критичности (1..5). */
    int severity();

    /**
     * Анализирует событие. Если условие сработало — возвращает черновик инцидента.
     */
    Optional<IncidentDraft> evaluate(AuditEventCreated event, AuditLogRepository auditLogRepository);
}