ALTER TABLE incidents
    ALTER COLUMN notified DROP NOT NULL,
    ALTER COLUMN notified SET DEFAULT false;