package reports

import "errors"

// Custom report generation errors
var (
	ErrTemplateNotFound          = errors.New("custom report template not found")
	ErrParameterValidationFailed = errors.New("parameter validation failed")
	ErrInvalidQuery              = errors.New("invalid custom query")
	ErrDataSourceNotSupported    = errors.New("data source not supported")
	ErrQueryComplexityTooHigh    = errors.New("query complexity too high")
	ErrPaginationRequired        = errors.New("pagination required for large dataset")
	ErrStreamTokenInvalid        = errors.New("invalid stream token")
	ErrTemplateAccessDenied      = errors.New("access denied to template")
	ErrScheduleInvalid           = errors.New("invalid schedule configuration")
	ErrDeliveryConfigInvalid     = errors.New("invalid delivery configuration")
	ErrExportFormatNotSupported  = errors.New("export format not supported for custom reports")
	ErrTenantIsolationViolation  = errors.New("tenant isolation violation")
)
