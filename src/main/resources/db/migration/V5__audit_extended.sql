-- =========================================================
-- V5: Расширение журнала аудита
--   - severity (1..5)
--   - category (AUTH/ACCESS/USER_MGMT/...)
--   - correlation_id (для связки событий)
--   - hash chain: prev_hash + hash + seq (защита от подделки)
-- =========================================================

ALTER TABLE audit_log
    ADD COLUMN IF NOT EXISTS severity        INT          NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS category        VARCHAR(30)  NOT NULL DEFAULT 'AUTH',
    ADD COLUMN IF NOT EXISTS correlation_id  UUID,
    ADD COLUMN IF NOT EXISTS country_code    CHAR(2),
    ADD COLUMN IF NOT EXISTS prev_hash       VARCHAR(64),
    ADD COLUMN IF NOT EXISTS hash            VARCHAR(64),
    ADD COLUMN IF NOT EXISTS seq             BIGSERIAL;

ALTER TABLE audit_log
    ADD CONSTRAINT chk_audit_severity CHECK (severity BETWEEN 1 AND 5);

CREATE INDEX IF NOT EXISTS idx_audit_severity      ON audit_log(severity);
CREATE INDEX IF NOT EXISTS idx_audit_category      ON audit_log(category);
CREATE INDEX IF NOT EXISTS idx_audit_correlation   ON audit_log(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_ip            ON audit_log(ip);
CREATE INDEX IF NOT EXISTS idx_audit_seq           ON audit_log(seq);
CREATE INDEX IF NOT EXISTS idx_audit_action_ts     ON audit_log(action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_ts      ON audit_log(actor_username, ts DESC);

-- Таблица-сентинель для синхронизации хеш-цепочки.
-- Содержит ровно одну строку. Перед вставкой нового лога мы делаем
-- SELECT ... FOR UPDATE по этой строке, чтобы избежать гонок.
CREATE TABLE IF NOT EXISTS audit_chain_state (
    id           INT PRIMARY KEY,
    last_hash    VARCHAR(64) NOT NULL,
    last_seq     BIGINT      NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO audit_chain_state(id, last_hash, last_seq)
VALUES (1, 'GENESIS', 0)
ON CONFLICT (id) DO NOTHING;