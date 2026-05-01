package com.example.securitycourse.audit;

/**
 * Возможные результаты выполнения действия, записываемые в журнал аудита.
 */
public enum AuditResults {

    /** Действие выполнено успешно. */
    SUCCESS,

    /** Действие завершилось ошибкой или было отклонено. */
    FAIL
}