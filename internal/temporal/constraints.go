package temporal

import (
	"slices"
	"time"
)

// Constraint represents a time-based policy restriction.
type Constraint struct {
	MaxContainerAge time.Duration  `json:"max_container_age,omitempty"`
	MinContainerAge time.Duration  `json:"min_container_age,omitempty"`
	TimeOfDay       *TimeRange     `json:"time_of_day,omitempty"`
	DaysOfWeek      []time.Weekday `json:"days_of_week,omitempty"`
}

// TimeRange represents a time-of-day window (UTC).
type TimeRange struct {
	Start TimeOfDay `json:"start"`
	End   TimeOfDay `json:"end"`
}

// TimeOfDay represents an hour:minute pair.
type TimeOfDay struct {
	Hour   int `json:"hour"`
	Minute int `json:"minute"`
}

func (td TimeOfDay) minutes() int {
	return td.Hour*60 + td.Minute
}

// Evaluate checks whether the event satisfies all constraints.
// containerAge is the duration since the container started.
// wallClock is the current wall clock time (UTC).
func Evaluate(c *Constraint, containerAge time.Duration, wallClock time.Time) bool {
	if c == nil {
		return true
	}

	if c.MaxContainerAge > 0 && containerAge > c.MaxContainerAge {
		return false
	}

	if c.MinContainerAge > 0 && containerAge < c.MinContainerAge {
		return false
	}

	if c.TimeOfDay != nil {
		nowMinutes := wallClock.Hour()*60 + wallClock.Minute()
		start := c.TimeOfDay.Start.minutes()
		end := c.TimeOfDay.End.minutes()

		if start <= end {
			if nowMinutes < start || nowMinutes > end {
				return false
			}
		} else {
			// Wraps midnight: e.g. 22:00-06:00
			if nowMinutes < start && nowMinutes > end {
				return false
			}
		}
	}

	if len(c.DaysOfWeek) > 0 && !slices.Contains(c.DaysOfWeek, wallClock.Weekday()) {
		return false
	}

	return true
}
