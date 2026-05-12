-- =========================================================
-- V6: Таблица инцидентов (результат корреляции)
-- =========================================================

CREATE TABLE IF NOT EXISTS incidents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rule_name         VARCHAR(100) NOT NULL,
    rule_description  TEXT,
    severity          INT          NOT NULL,
    status            VARCHAR(20)  NOT NULL DEFAULT 'NEW',
    affected_user     VARCHAR(100),
    source_ip         VARCHAR(64),
    description       TEXT,
    related_log_ids   TEXT, -- JSON-массив UUID связанных событий
    mitre_technique   VARCHAR(20), -- например: T1110.001
    assigned_to       UUID,
    resolved_at       TIMESTAMPTZ,
    resolution_notes  TEXT,
    notified          BOOLEAN      NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_incident_severity CHECK (severity BETWEEN 1 AND 5),
    CONSTRAINT chk_incident_status   CHECK (status IN ('NEW', 'ACK', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status_severity ON incidents(status, severity DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at      ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_rule            ON incidents(rule_name);
CREATE INDEX IF NOT EXISTS idx_incidents_user            ON incidents(affected_user);