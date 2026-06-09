// Package config provides configuration management for warmor
package config

// EnforcerConfig holds all configurable parameters for the enforcer
type EnforcerConfig struct {
	// Cache configuration
	CacheSize int
	CacheTTL  string // Duration string like "5m"

	// Backoff configuration
	InitialBackoff string // Duration string like "10ms"
	MaxBackoff     string // Duration string like "5s"

	// Metrics configuration
	MetricsPort int

	// Logging configuration
	LogLevel string

	// Policy configuration
	PolicyPath string

	// Version
	Version string
}

// DefaultConfig returns default configuration values
func DefaultConfig() *EnforcerConfig {
	return &EnforcerConfig{
		CacheSize:      10000,
		CacheTTL:       "5m",
		InitialBackoff: "10ms",
		MaxBackoff:     "5s",
		MetricsPort:    9090,
		LogLevel:       "info",
		PolicyPath:     "policies/example/policy.wasm",
		Version:        "1.1.0-beta",
	}
}