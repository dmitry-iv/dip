-- =====================================================================
-- V8: Настройки алертов (SMTP + получатели), редактируемые из админки.
-- Пароль SMTP хранится зашифрованным AES-GCM (см. EncryptionService).
--
-- Использует CREATE TABLE IF NOT EXISTS — таблица могла уже быть создана
-- автоматически через spring.jpa.hibernate.ddl-auto=update.
-- =====================================================================

CREATE TABLE IF NOT EXISTS alert_settings (
    id              SMALLINT     PRIMARY KEY DEFAULT 1,
    smtp_host       VARCHAR(255) NOT NULL DEFAULT 'smtp.yandex.ru',
    smtp_port       INT          NOT NULL DEFAULT 587,
    smtp_username   VARCHAR(255) NOT NULL DEFAULT '',
    smtp_password   VARCHAR(1024) NOT NULL DEFAULT '',
    sender_address  VARCHAR(255) NOT NULL DEFAULT '',
    recipients_csv  VARCHAR(2000) NOT NULL DEFAULT '',
    min_severity    INT          NOT NULL DEFAULT 4,
    throttle_seconds INT         NOT NULL DEFAULT 60,
    enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT alert_settings_singleton CHECK (id = 1)
);

INSERT INTO alert_settings (id, smtp_host, smtp_port, min_severity, throttle_seconds, enabled)
VALUES (1, 'smtp.yandex.ru', 587, 4, 60, FALSE)
ON CONFLICT (id) DO NOTHING;