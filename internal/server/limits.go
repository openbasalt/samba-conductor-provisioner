package server

import (
	"sync"
	"time"
)

// Ceiling kinds (the [limits] keys without "_per_hour").
const (
	limitTokenIssues  = "token_issues"
	limitPasswordSets = "password_sets"
	limitEnables      = "enables"
	limitCreates      = "creates"
	limitUpdates      = "updates"
	limitMoves        = "moves"
	limitDisables     = "disables"
)

// limiter enforces hourly ceilings with a sliding one-hour window per
// kind. It is in memory: a restart starts with empty windows. A ceiling of
// 0 refuses everything.
type limiter struct {
	mu       sync.Mutex
	ceilings map[string]int
	events   map[string][]time.Time
	warned   map[string]time.Time
}

func newLimiter(ceilings map[string]int) *limiter {
	return &limiter{ceilings: ceilings, events: map[string][]time.Time{}, warned: map[string]time.Time{}}
}

const window = time.Hour

// pruneLocked drops the events older than the window.
func (l *limiter) pruneLocked(kind string, now time.Time) []time.Time {
	ev := l.events[kind]
	i := 0
	for i < len(ev) && !ev[i].After(now.Add(-window)) {
		i++
	}
	ev = ev[i:]
	l.events[kind] = ev
	return ev
}

// allow records one event of kind when the ceiling allows it.
func (l *limiter) allow(kind string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := l.pruneLocked(kind, now)
	if len(ev) >= l.ceilings[kind] {
		return false
	}
	l.events[kind] = append(ev, now)
	return true
}

// shouldWarn reports whether a refusal of kind should be logged at
// warning level (at most once a minute per kind).
func (l *limiter) shouldWarn(kind string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.warned[kind]; ok && now.Sub(last) < time.Minute {
		return false
	}
	l.warned[kind] = now
	return true
}

// use returns the events in the window and the ceiling of kind.
func (l *limiter) use(kind string, now time.Time) (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pruneLocked(kind, now)), l.ceilings[kind]
}
