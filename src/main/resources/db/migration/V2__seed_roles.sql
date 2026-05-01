-- Insert explicit UUIDs to avoid failures when the roles.id column has no DEFAULT.
-- We use fixed UUID constants to avoid relying on PostgreSQL extensions.

INSERT INTO roles(id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'USER')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles(id, name) VALUES ('00000000-0000-0000-0000-000000000002', 'MANAGER')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles(id, name) VALUES ('00000000-0000-0000-0000-000000000003', 'ADMIN')
ON CONFLICT (name) DO NOTHING;
