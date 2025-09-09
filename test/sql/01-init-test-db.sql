-- CFGMS Test Database Initialization
-- Sets up clean test database for storage provider integration testing

-- Create additional test databases for isolation
CREATE DATABASE cfgms_test_rbac;
CREATE DATABASE cfgms_test_audit;  
CREATE DATABASE cfgms_test_config;
CREATE DATABASE cfgms_test_integration;

-- Grant permissions to test user
GRANT ALL PRIVILEGES ON DATABASE cfgms_test_rbac TO cfgms_test;
GRANT ALL PRIVILEGES ON DATABASE cfgms_test_audit TO cfgms_test;
GRANT ALL PRIVILEGES ON DATABASE cfgms_test_config TO cfgms_test;
GRANT ALL PRIVILEGES ON DATABASE cfgms_test_integration TO cfgms_test;

-- Connect to main test database
\c cfgms_test;

-- Create extensions that CFGMS might need
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For full-text search

-- Create test schema for namespace isolation
CREATE SCHEMA IF NOT EXISTS cfgms_test;
GRANT ALL PRIVILEGES ON SCHEMA cfgms_test TO cfgms_test;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cfgms_test TO cfgms_test;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cfgms_test TO cfgms_test;

-- Set default search path for test user
ALTER USER cfgms_test SET search_path = cfgms_test,public;

-- Insert test data fixtures
INSERT INTO cfgms_test.test_fixtures (name, description, created_at) VALUES 
    ('database_provider_test', 'Test fixture for database provider validation', NOW()),
    ('integration_test', 'Test fixture for integration testing', NOW())
ON CONFLICT DO NOTHING;