-- =========================================================
-- V3: Добавление полей для двухфакторной аутентификации (TOTP)
-- =========================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret      VARCHAR(64),
    ADD COLUMN IF NOT EXISTS totp_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS totp_enrolled_at TIMESTAMPTZ,
    -- хеши одноразовых backup-кодов (BCrypt), JSON-массив
    ADD COLUMN IF NOT EXISTS backup_codes     TEXT;

CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON users(totp_enabled);