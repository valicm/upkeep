package notify

import (
	"fmt"
	"strings"
	"time"
)

// Schedule says when the digest goes out: every day or every week at a set time, or whenever
// the findings change.
type Schedule struct {
	OnChange bool
	Weekly   bool         // else daily
	Day      time.Weekday // for Weekly
	Hour     int
	Minute   int
}

// DefaultSchedule is used when the configuration names none.
const DefaultSchedule = "daily 07:00"

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday, "wednesday": time.Wednesday,
	"thursday": time.Thursday, "friday": time.Friday, "saturday": time.Saturday,
}

// ParseSchedule reads "daily HH:MM", "weekly <day> HH:MM" or "on change". Case and extra
// spaces do not matter; a day is its English name or the first three letters of it.
func ParseSchedule(s string) (Schedule, error) {
	if strings.TrimSpace(s) == "" {
		s = DefaultSchedule
	}
	words := strings.Fields(strings.ToLower(s))
	bad := fmt.Errorf("schedule %q is not \"daily HH:MM\", \"weekly <day> HH:MM\" or \"on change\"", s)
	var sch Schedule
	var clock string
	switch {
	case len(words) == 2 && words[0] == "on" && words[1] == "change":
		return Schedule{OnChange: true}, nil
	case len(words) == 2 && words[0] == "daily":
		clock = words[1]
	case len(words) == 3 && words[0] == "weekly":
		day, ok := weekdays[words[1]]
		if !ok {
			return Schedule{}, bad
		}
		sch.Weekly, sch.Day, clock = true, day, words[2]
	default:
		return Schedule{}, bad
	}
	t, err := time.Parse("15:04", clock)
	if err != nil {
		return Schedule{}, bad
	}
	sch.Hour, sch.Minute = t.Hour(), t.Minute()
	return sch, nil
}

// Last returns the latest moment, not after now, at which a daily or weekly digest was due,
// in now's time zone. A digest is due when none was sent since then. Whole days are stepped
// by the calendar, not by 24 hours, so the hour stays the same across a clock change.
func (s Schedule) Last(now time.Time) time.Time {
	y, m, d := now.Date()
	for back := 0; back <= 7; back++ {
		slot := time.Date(y, m, d-back, s.Hour, s.Minute, 0, 0, now.Location())
		if slot.After(now) || (s.Weekly && slot.Weekday() != s.Day) {
			continue
		}
		return slot
	}
	return time.Time{} // not reached: one of eight days in a row matches
}
