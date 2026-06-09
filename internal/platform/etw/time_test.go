//go:build windows
// +build windows

package etw

import (
	"testing"
	"time"
)

func TestFiletimeToTime(t *testing.T) {
	// 2021-01-01T00:00:00Z expressed as a Windows FILETIME (100ns ticks since
	// 1601-01-01 UTC).
	want := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	const epochDeltaSeconds = 11644473600
	ft := (want.Unix() + epochDeltaSeconds) * 10_000_000

	got := filetimeToTime(ft)
	if !got.Equal(want) {
		t.Errorf("filetimeToTime(%d) = %v, want %v", ft, got, want)
	}
}

func TestFiletimeToTime_NonPositiveFallsBackToNow(t *testing.T) {
	before := time.Now()
	got := filetimeToTime(0)
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("filetimeToTime(0) = %v, want a value within [%v, %v]", got, before, after)
	}
}
