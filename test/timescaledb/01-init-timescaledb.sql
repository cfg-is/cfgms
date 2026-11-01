-- Initialize TimescaleDB for CFGMS testing (unified for logging and HA tests)
-- This script sets up the database with TimescaleDB extension and creates
-- necessary users and permissions for testing.

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create additional user for logging tests (if needed)
-- Note: Password is set via environment variable in Docker container
-- The cfgms_test user is created by Docker's POSTGRES_USER env var

-- Grant necessary permissions to unified cfgms_test user
GRANT ALL PRIVILEGES ON DATABASE cfgms_ha_test TO cfgms_test;
GRANT ALL PRIVILEGES ON SCHEMA public TO cfgms_test;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cfgms_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cfgms_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cfgms_test;

-- Create test schema for isolated testing
CREATE SCHEMA IF NOT EXISTS test_logging;
GRANT ALL PRIVILEGES ON SCHEMA test_logging TO cfgms_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON TABLES TO cfgms_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON SEQUENCES TO cfgms_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON FUNCTIONS TO cfgms_test;

-- Verify TimescaleDB is working (license info may not be available in all versions)
DO $$
BEGIN
    -- Try to query license info, ignore errors if table doesn't exist
    BEGIN
        PERFORM 1 FROM timescaledb_information.license LIMIT 1;
        RAISE NOTICE 'TimescaleDB license information available';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'TimescaleDB license information not available (this is normal for some versions)';
    END;
END
$$;

-- Display TimescaleDB version for debugging (may not be available in all versions)
DO $$
BEGIN
    BEGIN
        RAISE NOTICE 'Checking TimescaleDB version...';
        PERFORM 1 FROM timescaledb_information.version LIMIT 1;
        RAISE NOTICE 'TimescaleDB version information available';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'TimescaleDB version information not available (this is normal for some versions)';
    END;
END
$$;