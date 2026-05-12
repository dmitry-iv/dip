-- =========================================================
-- V4: Тип пользователя (LOCAL / AD / EXTERNAL) и срок действия
-- =========================================================
-- LOCAL    — администраторы, заводятся вручную в системе
-- AD       — сотрудники, аутентификация через Active Directory
-- EXTERNAL — подрядчики/аудиторы, локальная БД + ОБЯЗАТЕЛЬНОЕ 2FA
-- =========================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS user_source  VARCHAR(20) NOT NULL DEFAULT 'LOCAL',
    ADD COLUMN IF NOT EXISTS external_id  VARCHAR(200),
    ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(64),
    ADD COLUMN IF NOT EXISTS last_login_country CHAR(2);

ALTER TABLE users
    ADD CONSTRAINT chk_user_source
    CHECK (user_source IN ('LOCAL', 'AD', 'EXTERNAL'));

CREATE INDEX IF NOT EXISTS idx_users_source     ON users(user_source);
CREATE INDEX IF NOT EXISTS idx_users_expires_at ON users(expires_at);