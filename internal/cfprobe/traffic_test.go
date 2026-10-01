package cfprobe

import (
	"testing"
	"time"
)

func TestPeriodStartTSClampsResetDay(t *testing.T) {
	now := time.Date(2026, time.February, 15, 12, 0, 0, 0, time.UTC)
	got := time.Unix(periodStartTS(now, 31), 0).UTC()
	want := time.Date(2026, time.January, 31, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestPeriodStartTSRollsMissingResetDayToNextMonth(t *testing.T) {
	now := time.Date(2026, time.April, 30, 12, 0, 0, 0, time.UTC)
	got := time.Unix(periodStartTS(now, 31), 0).UTC()
	want := time.Date(2026, time.March, 31, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestPeriodStartTSNoReset(t *testing.T) {
	if got := periodStartTS(time.Date(2026, time.August, 4, 0, 0, 0, 0, time.UTC), 0); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestAdvanceTrafficStateTracksMonthlyAndDailyCounters(t *testing.T) {
	start := time.Date(2026, time.September, 25, 10, 0, 0, 0, time.Local)
	state := trafficState{}
	advanceTrafficState(&state, NetBytes{RX: 1_000, TX: 2_000}, start, 1, "eth0")
	advanceTrafficState(&state, NetBytes{RX: 1_250, TX: 2_400}, start.Add(2*time.Second), 1, "eth0")

	if state.RXPeriod != 250 || state.TXPeriod != 400 {
		t.Fatalf("period traffic = %d/%d, want 250/400", state.RXPeriod, state.TXPeriod)
	}
	if state.RXDaily != 250 || state.TXDaily != 400 {
		t.Fatalf("daily traffic = %d/%d, want 250/400", state.RXDaily, state.TXDaily)
	}
}

func TestAdvanceTrafficStateResetsDailyAtLocalMidnight(t *testing.T) {
	beforeMidnight := time.Date(2026, time.September, 25, 23, 59, 59, 0, time.Local)
	state := trafficState{}
	advanceTrafficState(&state, NetBytes{RX: 1_000, TX: 2_000}, beforeMidnight, 1, "eth0")
	advanceTrafficState(&state, NetBytes{RX: 1_100, TX: 2_200}, beforeMidnight.Add(time.Second), 1, "eth0")

	if state.RXDaily != 100 || state.TXDaily != 200 {
		t.Fatalf("daily traffic after midnight = %d/%d, want 100/200", state.RXDaily, state.TXDaily)
	}
	if state.RXPeriod != 100 || state.TXPeriod != 200 {
		t.Fatalf("monthly traffic after midnight = %d/%d, want 100/200", state.RXPeriod, state.TXPeriod)
	}
}

func TestAdvanceTrafficStateHandlesCounterReset(t *testing.T) {
	start := time.Date(2026, time.September, 25, 10, 0, 0, 0, time.Local)
	state := trafficState{}
	advanceTrafficState(&state, NetBytes{RX: 1_000, TX: 2_000}, start, 1, "eth0")
	advanceTrafficState(&state, NetBytes{RX: 25, TX: 40}, start.Add(2*time.Second), 1, "eth0")

	if state.RXDaily != 25 || state.TXDaily != 40 {
		t.Fatalf("daily traffic after reset = %d/%d, want 25/40", state.RXDaily, state.TXDaily)
	}
}

func TestLocalTrafficDayBoundsUseCalendarMidnight(t *testing.T) {
	location := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2026, time.September, 30, 23, 59, 30, 0, location)
	wantStart := time.Date(2026, time.September, 30, 0, 0, 0, 0, location)
	wantEnd := time.Date(2026, time.October, 1, 0, 0, 0, 0, location)

	if got := startOfLocalDay(now); !got.Equal(wantStart) {
		t.Fatalf("day start = %s, want %s", got, wantStart)
	}
	if got := endOfLocalDay(now); !got.Equal(wantEnd) {
		t.Fatalf("day end = %s, want %s", got, wantEnd)
	}
}
