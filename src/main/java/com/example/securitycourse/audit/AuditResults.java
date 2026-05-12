package com.example.securitycourse.audit;

/** Результат выполнения действия. */
public enum AuditResults {

    /** Успешно. */
    SUCCESS,

    /** Неудача (отказ). */
    FAIL,

    /** Только информационная запись (например, генерация инцидента). */
    INFO
}