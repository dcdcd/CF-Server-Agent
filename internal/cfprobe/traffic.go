package cfprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type trafficState struct {
	RXPrev      uint64
	TXPrev      uint64
	RXPeriod    uint64
	TXPeriod    uint64
	RXDaily     uint64
	TXDaily     uint64
	LastCheck   int64
	PeriodStart int64
	DayStart    int64
	Interface   string
}

func readTrafficState(path string) trafficState {
	values, err := parseKVFile(path)
	if err != nil {
		return trafficState{}
	}
	return trafficState{
		RXPrev:      parseUintDefault(values["RX_PREV"], 0),
		TXPrev:      parseUintDefault(values["TX_PREV"], 0),
		RXPeriod:    parseUintDefault(values["RX_PERIOD"], 0),
		TXPeriod:    parseUintDefault(values["TX_PERIOD"], 0),
		RXDaily:     parseUintDefault(values["RX_DAILY"], 0),
		TXDaily:     parseUintDefault(values["TX_DAILY"], 0),
		LastCheck:   atoi64Default(values["LAST_CHECK"], 0),
		PeriodStart: atoi64Default(values["PERIOD_START"], 0),
		DayStart:    atoi64Default(values["DAY_START"], 0),
		Interface:   values["INTERFACE"],
	}
}

func writeTrafficState(path string, st trafficState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data := fmt.Sprintf("RX_PREV=%d\nTX_PREV=%d\nRX_PERIOD=%d\nTX_PERIOD=%d\nRX_DAILY=%d\nTX_DAILY=%d\nLAST_CHECK=%d\nPERIOD_START=%d\nDAY_START=%d\nINTERFACE=%s\n",
		st.RXPrev, st.TXPrev, st.RXPeriod, st.TXPeriod, st.RXDaily, st.TXDaily, st.LastCheck, st.PeriodStart, st.DayStart, st.Interface)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// advanceTrafficState keeps monthly and local-calendar-day counters in memory.
// Callers decide when to persist the state so a short realtime interval does
// not turn into the same frequency of disk writes.
func advanceTrafficState(st *trafficState, current NetBytes, now time.Time, resetDay int, iface string) (boundaryChanged bool) {
	if st.Interface != iface {
		*st = trafficState{}
	}

	periodStart := periodStartTS(now, resetDay)
	dayStart := startOfLocalDay(now).Unix()
	if st.LastCheck == 0 {
		st.RXPrev = current.RX
		st.TXPrev = current.TX
		st.LastCheck = now.Unix()
		st.PeriodStart = periodStart
		st.DayStart = dayStart
		st.Interface = iface
		return true
	}

	rxDelta := trafficCounterDelta(st.RXPrev, current.RX)
	txDelta := trafficCounterDelta(st.TXPrev, current.TX)
	periodChanged := periodStart != 0 && st.PeriodStart != 0 && periodStart != st.PeriodStart
	dayChanged := st.DayStart != 0 && dayStart != st.DayStart

	if periodChanged {
		st.RXPeriod = rxDelta
		st.TXPeriod = txDelta
	} else {
		st.RXPeriod += rxDelta
		st.TXPeriod += txDelta
	}
	if dayChanged {
		st.RXDaily = rxDelta
		st.TXDaily = txDelta
	} else if st.DayStart == 0 {
		// Existing state files predate daily counters. Start from the first
		// sample after upgrade; the next local midnight is fully exact.
		st.RXDaily = rxDelta
		st.TXDaily = txDelta
	} else {
		st.RXDaily += rxDelta
		st.TXDaily += txDelta
	}

	st.RXPrev = current.RX
	st.TXPrev = current.TX
	st.LastCheck = now.Unix()
	st.PeriodStart = periodStart
	st.DayStart = dayStart
	st.Interface = iface
	return periodChanged || dayChanged
}

func trafficCounterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	// A reboot or counter reset starts a new sequence at current.
	return current
}

func startOfLocalDay(now time.Time) time.Time {
	year, month, day := now.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, now.Location())
}

func endOfLocalDay(now time.Time) time.Time {
	year, month, day := now.Date()
	return time.Date(year, month, day+1, 0, 0, 0, 0, now.Location())
}

func applyTrafficCorrection(path string, current NetBytes, iface string, rxGB, txGB string) error {
	rx, err := parseTrafficCorrectionGB(rxGB)
	if err != nil {
		return err
	}
	tx, err := parseTrafficCorrectionGB(txGB)
	if err != nil {
		return err
	}
	st := readTrafficState(path)
	st.RXPrev = current.RX
	st.TXPrev = current.TX
	st.RXPeriod = rx
	st.TXPeriod = tx
	st.LastCheck = time.Now().Unix()
	if st.DayStart == 0 {
		st.DayStart = startOfLocalDay(time.Now()).Unix()
	}
	st.Interface = iface
	return writeTrafficState(path, st)
}

func periodStartTS(now time.Time, resetDay int) int64 {
	if resetDay == 0 {
		return 0
	}
	if resetDay < 1 || resetDay > 31 {
		return now.Unix()
	}
	return lastResetDate(now, resetDay).Unix()
}

func lastResetDate(now time.Time, resetDay int) time.Time {
	year, month, _ := now.Date()
	loc := now.Location()
	thisMonth := actualResetDate(year, month, resetDay, loc)
	if !now.Before(thisMonth) {
		return thisMonth
	}
	prevMonth := month - 1
	prevYear := year
	if prevMonth < time.January {
		prevMonth = time.December
		prevYear--
	}
	return actualResetDate(prevYear, prevMonth, resetDay, loc)
}

func actualResetDate(year int, month time.Month, resetDay int, loc *time.Location) time.Time {
	firstDayOfNextMonth := time.Date(year, month+1, 1, 0, 0, 0, 0, loc)
	lastDayOfMonth := firstDayOfNextMonth.AddDate(0, 0, -1).Day()
	if resetDay <= lastDayOfMonth {
		return time.Date(year, month, resetDay, 0, 0, 0, 0, loc)
	}
	nextMonth := month + 1
	nextYear := year
	if nextMonth > time.December {
		nextMonth = time.January
		nextYear++
	}
	return time.Date(nextYear, nextMonth, 1, 0, 0, 0, 0, loc)
}

func parseUintDefault(raw string, def uint64) uint64 {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return def
	}
	return n
}
