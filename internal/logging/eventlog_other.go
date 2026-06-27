//go:build !windows
// +build !windows

package logging

import "io"

// NewLoggerWithEventLog is a no-op on non-Windows platforms; it returns a
// standard logger writing to w only.
func NewLoggerWithEventLog(level string, w io.Writer, _ string) (*Logger, error) {
	return NewLoggerWithWriter(level, w), nil
}
