# Configuration Storage

## Overview

CFGMS implements a flexible storage system for configurations that supports both file-based and database implementations. The storage system is designed to be pluggable, allowing for different storage backends to be used based on deployment requirements.

For a high-level overview of the configuration management system, see [Configuration Management Overview](./overview.md).
For information about configuration types, see [Configuration Types](./configuration-types.md).

## Storage Interface

The storage system is defined by a common interface that all storage implementations must satisfy:

```go
type ConfigStorage interface {
    // Store stores a configuration
    Store(ctx context.Context, cfg *Config) error
    
    // Get retrieves a configuration by ID
    Get(ctx context.Context, id string) (*Config, error)
    
    // List retrieves all configurations of a given type
    List(ctx context.Context, cfgType string) ([]*Config, error)
    
    // Delete deletes a configuration by ID
    Delete(ctx context.Context, id string) error
    
    // Exists checks if a configuration exists
    Exists(ctx context.Context, id string) (bool, error)
    
    // GetHistory retrieves the history of a configuration
    GetHistory(ctx context.Context, id string) ([]*Config, error)
}
```

## File-based Storage

The default storage implementation uses a file-based system with Git integration for version control.

```go
type FileStorage struct {
    baseDir string
    git     *git.Repository
}

func (s *FileStorage) Store(ctx context.Context, cfg *Config) error {
    // Write configuration to file
    path := filepath.Join(s.baseDir, cfg.Type, cfg.ID+".yaml")
    data, err := yaml.Marshal(cfg)
    if err != nil {
        return fmt.Errorf("marshal config: %w", err)
    }
    
    if err := os.WriteFile(path, data, 0644); err != nil {
        return fmt.Errorf("write file: %w", err)
    }
    
    // Commit to Git
    if err := s.git.Add(path); err != nil {
        return fmt.Errorf("git add: %w", err)
    }
    
    if err := s.git.Commit(fmt.Sprintf("Update %s configuration", cfg.ID)); err != nil {
        return fmt.Errorf("git commit: %w", err)
    }
    
    return nil
}
```

### Directory Structure

```
/cfgms/
  ├── system/
  │   ├── meta/
  │   │   ├── controller.yaml
  │   │   ├── auth.yaml
  │   │   └── storage.yaml
  │   └── workflows/
  │       ├── backup.yaml
  │       └── update.yaml
  ├── endpoints/
  │   ├── web-servers/
  │   │   ├── nginx.yaml
  │   │   └── apache.yaml
  │   └── databases/
  │       ├── mysql.yaml
  │       └── postgres.yaml
  └── modules/
      ├── files/
      │   └── file.yaml
      └── services/
          └── service.yaml
```

### Git Integration

The file-based storage implementation includes Git integration for:

1. **Version Control** - Track changes to configurations
2. **History** - View and revert changes
3. **Audit Trail** - Track who made changes and when
4. **Branching** - Support for feature branches and testing
5. **Merge Conflicts** - Handle concurrent modifications

## Database Storage

For larger deployments, CFGMS supports database storage implementations.

```go
type DatabaseStorage struct {
    db *sql.DB
}

func (s *DatabaseStorage) Store(ctx context.Context, cfg *Config) error {
    tx, err := s.db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("begin transaction: %w", err)
    }
    defer tx.Rollback()
    
    // Store configuration
    if err := s.storeConfig(ctx, tx, cfg); err != nil {
        return err
    }
    
    // Store history
    if err := s.storeHistory(ctx, tx, cfg); err != nil {
        return err
    }
    
    return tx.Commit()
}
```

### Supported Databases

1. **PostgreSQL** - Primary database implementation
2. **MySQL** - Alternative database implementation
3. **SQLite** - Lightweight implementation for testing

### Database Schema

```sql
CREATE TABLE configurations (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(255) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE configuration_history (
    id VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (id, version)
);
```

## Storage Factory

The storage factory creates the appropriate storage backend based on configuration:

```go
type StorageFactory struct {
    config *StorageConfig
}

func (f *StorageFactory) Create() (ConfigStorage, error) {
    switch f.config.Type {
    case "file":
        return NewFileStorage(f.config.FileConfig)
    case "postgres":
        return NewPostgresStorage(f.config.PostgresConfig)
    case "mysql":
        return NewMySQLStorage(f.config.MySQLConfig)
    case "sqlite":
        return NewSQLiteStorage(f.config.SQLiteConfig)
    default:
        return nil, fmt.Errorf("unknown storage type: %s", f.config.Type)
    }
}
```

## Storage Configuration

Storage configuration is defined in the system configuration:

```yaml
storage:
  type: file  # or postgres, mysql, sqlite
  file:
    base_dir: /cfgms
    git:
      enabled: true
      remote: git@github.com:org/cfgms.git
  postgres:
    host: localhost
    port: 5432
    database: cfgms
    user: cfgms
    password: ${DB_PASSWORD}
```

For information about system configuration, see [Configuration Types](./configuration-types.md).

## Related Documentation

- [Configuration Management Overview](./overview.md): Introduction to configuration management in CFGMS
- [Configuration Types](./configuration-types.md): Different types of configurations and their purposes
- [Configuration Resolution](./configuration-resolution.md): How configurations are resolved and applied
- [Configuration Validation](./configuration-validation.md): Schema validation and error handling

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
