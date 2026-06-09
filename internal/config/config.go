// Package config provides configuration management for warmor.
//
// Currently unused — the daemon's CLI flags (cmd/warmor-daemon/main.go) and
// the enforcer constructor serve as the source of defaults. This package is
// retained as a placeholder for when configuration is loaded from a file or
// environment variables.
package config

// // EnforcerConfig holds all configurable parameters for the enforcer.
// type EnforcerConfig struct {
// 	CacheSize      int
// 	CacheTTL       string // Duration string like "5m"
// 	InitialBackoff string // Duration string like "10ms"
// 	MaxBackoff     string // Duration string like "5s"
// 	MetricsPort    int
// 	LogLevel       string
// 	PolicyPath     string
// 	Version        string
// }
//
// // DefaultConfig returns default configuration values.
// func DefaultConfig() *EnforcerConfig {
// 	return &EnforcerConfig{
// 		CacheSize:      10000,
// 		CacheTTL:       "5m",
// 		InitialBackoff: "10ms",
// 		MaxBackoff:     "5s",
// 		MetricsPort:    9090,
// 		LogLevel:       "info",
// 		PolicyPath:     "policies/example/policy.wasm",
// 		Version:        "1.1.0-beta",
// 	}
// }
