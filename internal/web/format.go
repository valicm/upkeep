package web

import (
	"fmt"
	"strconv"
	"time"
)

// timeView is one moment as a page shows it: short and relative, with the exact time kept for
// the tooltip and for scripts.
type timeView struct {
	Zero  bool
	Rel   string // "3 h ago"
	Exact string // "2026-11-19 09:12:05 UTC"
	ISO   string // RFC 3339, for <time datetime>
}

func newTimeView(t, now time.Time) timeView {
	if t.IsZero() {
		return timeView{Zero: true, Rel: "never"}
	}
	return timeView{
		Rel:   relTime(t, now),
		Exact: exactTime(t, now),
		ISO:   t.UTC().Format(time.RFC3339),
	}
}

// exactTime prints t in the zone of now, which is the server's: on a home network that is also
// the reader's. The script rewrites it to the browser's zone when it runs.
func exactTime(t, now time.Time) string {
	return t.In(now.Location()).Format("2006-01-02 15:04:05 MST")
}

// relTime says how long ago t was. A time slightly in the future is a clock that runs ahead,
// not news, so it reads as "just now".
func relTime(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d <= -time.Minute:
		return "in " + span(-d)
	case d < time.Minute:
		return "just now"
	}
	return span(d) + " ago"
}

// span prints a duration with one unit, the largest that still says something: nobody needs
// "2 d 3 h 12 min" to decide what to do.
func span(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 2*day:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	case d < 14*day:
		return strconv.Itoa(int(d/day)) + " d"
	case d < 60*day:
		return strconv.Itoa(int(d/(7*day))) + " wk"
	case d < 730*day:
		return strconv.Itoa(int(d/(30*day))) + " mo"
	}
	return strconv.Itoa(int(d/(365*day))) + " y"
}

// count prints "1 package" or "12 packages".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// shortDigest keeps enough of "sha256:..." to tell two images apart at a glance.
func shortDigest(d string) string {
	const keep = len("sha256:") + 8
	if len(d) > keep {
		return d[:keep] + "…"
	}
	return d
}
