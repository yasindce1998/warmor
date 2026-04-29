package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Logger is the global logger instance
var Logger zerolog.Logger

// Config holds logging configuration
type Config struct {
	Level      string // debug, info, warn, error
	Format     string // json, console
	Output     string // stdout, stderr, file path
	TimeFormat string // RFC3339, Unix, etc.
}

// DefaultConfig returns default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		TimeFormat: time.RFC3339,
	}
}

// Init initializes the global logger with the given configuration
func Init(config *Config) error {
	if config == nil {
		config = DefaultConfig()
	}

	// Set log level
	level, err := zerolog.ParseLevel(config.Level)
	if err != nil {
		return err
	}
	zerolog.SetGlobalLevel(level)

	// Set time format
	zerolog.TimeFieldFormat = config.TimeFormat

	// Determine output writer
	var output io.Writer
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// Assume it's a file path
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		output = file
	}

	// Set format
	if config.Format == "console" {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: time.RFC3339,
		}
	}

	// Create logger
	Logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Str("service", "warmor").
		Logger()

	// Set as global logger
	log.Logger = Logger

	return nil
}

// WithComponent creates a child logger with a component field
func WithComponent(component string) zerolog.Logger {
	return Logger.With().Str("component", component).Logger()
}

// WithFields creates a child logger with custom fields
func WithFields(fields map[string]interface{}) zerolog.Logger {
	ctx := Logger.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// Debug logs a debug message
func Debug(msg string) {
	Logger.Debug().Msg(msg)
}

// Info logs an info message
func Info(msg string) {
	Logger.Info().Msg(msg)
}

// Warn logs a warning message
func Warn(msg string) {
	Logger.Warn().Msg(msg)
}

// Error logs an error message
func Error(msg string, err error) {
	Logger.Error().Err(err).Msg(msg)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, err error) {
	Logger.Fatal().Err(err).Msg(msg)
}

// PolicyEvent logs a policy enforcement event
func PolicyEvent(action string, uid int, process string, decision string, reason string) {
	Logger.Info().
		Str("event_type", "policy_enforcement").
		Str("action", action).
		Int("uid", uid).
		Str("process", process).
		Str("decision", decision).
		Str("reason", reason).
		Msg("Policy enforcement decision")
}

// EBPFEvent logs an eBPF event
func EBPFEvent(eventType string, pid int, comm string) {
	Logger.Debug().
		Str("event_type", "ebpf").
		Str("ebpf_event", eventType).
		Int("pid", pid).
		Str("comm", comm).
		Msg("eBPF event received")
}

// WASMEvent logs a WASM execution event
func WASMEvent(function string, duration time.Duration, success bool) {
	Logger.Debug().
		Str("event_type", "wasm").
		Str("function", function).
		Dur("duration", duration).
		Bool("success", success).
		Msg("WASM function executed")
}

// MetricEvent logs a metric collection event
func MetricEvent(metric string, value float64, labels map[string]string) {
	event := Logger.Debug().
		Str("event_type", "metric").
		Str("metric", metric).
		Float64("value", value)

	for k, v := range labels {
		event = event.Str(k, v)
	}

	event.Msg("Metric collected")
}

// Made with Bob
