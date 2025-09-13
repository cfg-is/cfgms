-- Initialize TimescaleDB for CFGMS logging provider testing
-- This script sets up the database with TimescaleDB extension and creates
-- necessary users and permissions for testing.

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create additional user for logging tests (if needed)
-- Note: Password is set via environment variable in Docker container
-- The cfgms_logger_test user is created by Docker's POSTGRES_USER env var

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE cfgms_logs_test TO cfgms_logger_test;
GRANT ALL PRIVILEGES ON SCHEMA public TO cfgms_logger_test;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cfgms_logger_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO cfgms_logger_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO cfgms_logger_test;

-- Create test schema for isolated testing
CREATE SCHEMA IF NOT EXISTS test_logging;
GRANT ALL PRIVILEGES ON SCHEMA test_logging TO cfgms_logger_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON TABLES TO cfgms_logger_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON SEQUENCES TO cfgms_logger_test;
ALTER DEFAULT PRIVILEGES IN SCHEMA test_logging GRANT ALL ON FUNCTIONS TO cfgms_logger_test;

-- Verify TimescaleDB is working
SELECT * FROM timescaledb_information.license;

-- Display TimescaleDB version for debugging
SELECT * FROM timescaledb_information.version;