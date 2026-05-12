-- =========================================================
-- V7: Чёрный список JWT-токенов (для logout / принудительного отзыва)
-- =========================================================

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        UUID PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    user_id    UUID,
    reason     VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);