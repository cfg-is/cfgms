-- Create test fixture tables for storage provider validation
-- These tables simulate the basic structure CFGMS storage providers expect

\c cfgms_test;

-- Test fixtures table for tracking test data
CREATE TABLE IF NOT EXISTS cfgms_test.test_fixtures (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Grant permissions
GRANT ALL PRIVILEGES ON TABLE cfgms_test.test_fixtures TO cfgms_test;
GRANT USAGE, SELECT ON SEQUENCE cfgms_test.test_fixtures_id_seq TO cfgms_test;

-- Create test data for storage provider validation
INSERT INTO cfgms_test.test_fixtures (name, description, metadata) VALUES 
    ('client_tenant_test', 'Test client tenant for provider validation', '{"type": "client_tenant", "test": true}'),
    ('config_test', 'Test configuration for provider validation', '{"type": "config", "test": true}'),
    ('audit_test', 'Test audit entry for provider validation', '{"type": "audit", "test": true}'),
    ('rbac_test', 'Test RBAC data for provider validation', '{"type": "rbac", "test": true}'),
    ('runtime_test', 'Test runtime data for provider validation', '{"type": "runtime", "test": true}')
ON CONFLICT (name) DO UPDATE SET 
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata;

-- Create indexes for performance testing
CREATE INDEX IF NOT EXISTS idx_test_fixtures_name ON cfgms_test.test_fixtures(name);
CREATE INDEX IF NOT EXISTS idx_test_fixtures_metadata ON cfgms_test.test_fixtures USING GIN(metadata);