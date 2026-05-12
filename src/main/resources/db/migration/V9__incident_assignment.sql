-- =====================================================================
-- V9: Поддержка назначения инцидентов на SOC-аналитика.
--   - assigned_user_id   — кто взял инцидент в работу (FK на users)
--   - assigned_at        — когда назначен
-- =====================================================================

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS assigned_user_id UUID,
    ADD COLUMN IF NOT EXISTS assigned_at      TIMESTAMPTZ;

-- Индекс для быстрых запросов "мои инциденты"
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_user
    ON incidents (assigned_user_id, status);

-- FK без каскада: если пользователя удалят, assignment обнулится
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_incidents_assigned_user'
    ) THEN
        ALTER TABLE incidents
            ADD CONSTRAINT fk_incidents_assigned_user
            FOREIGN KEY (assigned_user_id)
            REFERENCES users(id)
            ON DELETE SET NULL;
    END IF;
END $$;