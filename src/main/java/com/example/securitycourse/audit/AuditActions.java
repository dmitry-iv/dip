package com.example.securitycourse.audit;

/**
 * Перечень всех типов событий, фиксируемых в журнале аудита.
 * Каждое событие имеет категорию и базовый уровень критичности (1..5).
 *
 * Уровни критичности:
 *  1 — info       (штатные действия)
 *  2 — low        (незначительные изменения, требующие записи)
 *  3 — medium     (отказ доступа, единичный сбой)
 *  4 — high       (потенциальный инцидент, требует внимания SOC)
 *  5 — critical   (подтверждённая атака / нарушение целостности)
 */
public enum AuditActions {

    // ========== AUTH ==========
    LOGIN_SUCCESS               (AuditCategory.AUTH,      1),
    LOGIN_FAILURE               (AuditCategory.AUTH,      3),
    LOGOUT                      (AuditCategory.AUTH,      1),

    MFA_CHALLENGE_ISSUED        (AuditCategory.AUTH,      1),
    MFA_SUCCESS                 (AuditCategory.AUTH,      1),
    MFA_FAILURE                 (AuditCategory.AUTH,      4),
    MFA_ENABLED                 (AuditCategory.AUTH,      2),
    MFA_DISABLED                (AuditCategory.AUTH,      4),
    MFA_BACKUP_CODE_USED        (AuditCategory.AUTH,      3),

    PASSWORD_CHANGED            (AuditCategory.AUTH,      2),
    PASSWORD_RESET_REQUESTED    (AuditCategory.AUTH,      2),
    REGISTER                    (AuditCategory.AUTH,      2),

    ACCOUNT_LOCKED              (AuditCategory.AUTH,      4),
    ACCOUNT_UNLOCKED            (AuditCategory.AUTH,      2),

    JWT_REVOKED                 (AuditCategory.AUTH,      2),
    SESSION_HIJACK_SUSPECTED    (AuditCategory.AUTH,      5),

    // ========== USER_MGMT ==========
    USER_CREATED                (AuditCategory.USER_MGMT, 2),
    USER_UPDATED                (AuditCategory.USER_MGMT, 2),
    USER_DELETED                (AuditCategory.USER_MGMT, 4),
    USER_ENABLED                (AuditCategory.USER_MGMT, 2),
    USER_DISABLED               (AuditCategory.USER_MGMT, 3),
    USER_LOCKED                 (AuditCategory.USER_MGMT, 3),
    USER_UNLOCKED               (AuditCategory.USER_MGMT, 2),
    ROLES_CHANGED               (AuditCategory.USER_MGMT, 4),
    PRIVILEGE_ESCALATION        (AuditCategory.USER_MGMT, 5),

    // ========== ACCESS ==========
    ACCESS_DENIED               (AuditCategory.ACCESS,    3),
    UNAUTHORIZED_API_CALL       (AuditCategory.ACCESS,    4),
    SENSITIVE_DATA_ACCESS       (AuditCategory.ACCESS,    3),

    // ========== DATA ==========
    DATA_EXPORT                 (AuditCategory.DATA,      3),
    MASS_EXPORT                 (AuditCategory.DATA,      4),
    DATA_DELETION               (AuditCategory.DATA,      4),

    // ========== CONFIG ==========
    CONFIG_CHANGED              (AuditCategory.CONFIG,    4),
    AUDIT_RULE_MODIFIED         (AuditCategory.CONFIG,    5),

    // ========== NETWORK ==========
    UNUSUAL_IP                  (AuditCategory.NETWORK,   3),
    IMPOSSIBLE_TRAVEL           (AuditCategory.NETWORK,   5),
    OFF_HOURS_LOGIN             (AuditCategory.NETWORK,   2),

    // ========== INCIDENT (порождаются корреляцией) ==========
    BRUTE_FORCE_DETECTED        (AuditCategory.INCIDENT,  5),
    CREDENTIAL_STUFFING         (AuditCategory.INCIDENT,  5),
    ANOMALOUS_BEHAVIOR          (AuditCategory.INCIDENT,  4),

    // ========== INCIDENT LIFECYCLE (действия SOC-аналитика) ==========
    INCIDENT_ASSIGNED           (AuditCategory.INCIDENT,  2),
    INCIDENT_TRANSFERRED        (AuditCategory.INCIDENT,  2),
    INCIDENT_RESOLVED           (AuditCategory.INCIDENT,  2),
    INCIDENT_FALSE_POSITIVE     (AuditCategory.INCIDENT,  2),
    INCIDENT_STATUS_CHANGED     (AuditCategory.INCIDENT,  2),
    // ========== SYSTEM ==========
    APP_STARTED                 (AuditCategory.SYSTEM,    1),
    APP_STOPPED                 (AuditCategory.SYSTEM,    2),
    AUDIT_INTEGRITY_VIOLATION   (AuditCategory.SYSTEM,    5),
    AUDIT_INTEGRITY_VERIFIED    (AuditCategory.SYSTEM,    1);

    private final AuditCategory category;
    private final int defaultSeverity;

    AuditActions(AuditCategory category, int defaultSeverity) {
        this.category = category;
        this.defaultSeverity = defaultSeverity;
    }

    public AuditCategory getCategory() {
        return category;
    }

    public int getDefaultSeverity() {
        return defaultSeverity;
    }
}