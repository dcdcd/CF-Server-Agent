package cfprobe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSplitProbeTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
	}{
		{name: "host default", target: "example.com", wantHost: "example.com", wantPort: defaultMetricsTCPPort},
		{name: "host port", target: "example.com:8443", wantHost: "example.com", wantPort: 8443},
		{name: "ipv6 bracket", target: "[2001:db8::1]:443", wantHost: "2001:db8::1", wantPort: 443},
		{name: "ipv6 default", target: "2001:db8::1", wantHost: "2001:db8::1", wantPort: defaultMetricsTCPPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := splitProbeTarget(tt.target, defaultMetricsTCPPort)
			if err != nil {
				t.Fatalf("splitProbeTarget returned error: %v", err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("got %s:%d, want %s:%d", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func resetDNSCacheForTest(t *testing.T) {
	t.Helper()
	oldLookup := lookupIP
	dnsCacheMu.Lock()
	dnsCache = map[string]dnsCacheEntry{}
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		lookupIP = oldLookup
		dnsCacheMu.Lock()
		dnsCache = map[string]dnsCacheEntry{}
		dnsCacheMu.Unlock()
	})
}

func TestResolveFirstIPCachesDNSForThirtyMinutes(t *testing.T) {
	resetDNSCacheForTest(t)
	calls := 0
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}

	first, err := resolveFirstIP(context.Background(), "Example.COM")
	if err != nil {
		t.Fatalf("resolveFirstIP returned error: %v", err)
	}
	second, err := resolveFirstIP(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolveFirstIP returned error: %v", err)
	}
	if first != "192.0.2.1" || second != "192.0.2.1" {
		t.Fatalf("got %q and %q, want cached 192.0.2.1", first, second)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
	dnsCacheMu.RLock()
	entry := dnsCache["example.com"]
	dnsCacheMu.RUnlock()
	if !entry.expiresAt.After(time.Now().Add(29 * time.Minute)) {
		t.Fatalf("cache expires too soon: %s", entry.expiresAt)
	}
}

func TestResolveFirstIPRefreshesExpiredCache(t *testing.T) {
	resetDNSCacheForTest(t)
	dnsCacheMu.Lock()
	dnsCache["example.com"] = dnsCacheEntry{ip: "192.0.2.1", expiresAt: time.Now().Add(-time.Minute)}
	dnsCacheMu.Unlock()
	calls := 0
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.2")}}, nil
	}

	got, err := resolveFirstIP(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolveFirstIP returned error: %v", err)
	}
	if got != "192.0.2.2" {
		t.Fatalf("got %q, want refreshed 192.0.2.2", got)
	}
	if calls != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls)
	}
}

func TestResolveFirstIPSkipsDNSForIPLiteral(t *testing.T) {
	resetDNSCacheForTest(t)
	calls := 0
	lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return nil, errors.New("unexpected dns lookup")
	}

	got, err := resolveFirstIP(context.Background(), "192.0.2.10")
	if err != nil {
		t.Fatalf("resolveFirstIP returned error: %v", err)
	}
	if got != "192.0.2.10" {
		t.Fatalf("got %q, want literal IP", got)
	}
	if calls != 0 {
		t.Fatalf("lookup calls = %d, want 0", calls)
	}
}

func TestRetryMeasuredPingAcceptsLowLatency(t *testing.T) {
	calls := 0
	got, err := retryMeasuredPing("tcp", func() (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("retryMeasuredPing returned error: %v", err)
	}
	if got != 42 || calls != 1 {
		t.Fatalf("got latency=%d calls=%d, want latency=42 calls=1", got, calls)
	}
}

func TestRetryMeasuredPingRejectsSuspiciousTCPRetransmission(t *testing.T) {
	values := []int{1200, 100}
	calls := 0
	got, err := retryMeasuredPing("tcp", func() (int, error) {
		v := values[calls]
		calls++
		return v, nil
	})
	if err == nil || !strings.Contains(err.Error(), "suspicious retransmission") {
		t.Fatalf("error = %v, want suspicious retransmission", err)
	}
	if got != -1 || calls != 2 {
		t.Fatalf("got latency=%d calls=%d, want latency=-1 calls=2", got, calls)
	}
}

func TestRetryMeasuredPingAcceptsRecoveredHTTP(t *testing.T) {
	values := []int{1200, 100}
	calls := 0
	got, err := retryMeasuredPing("http", func() (int, error) {
		v := values[calls]
		calls++
		return v, nil
	})
	if err != nil {
		t.Fatalf("retryMeasuredPing returned error: %v", err)
	}
	if got != 100 || calls != 2 {
		t.Fatalf("got latency=%d calls=%d, want latency=100 calls=2", got, calls)
	}
}

func TestRetryMeasuredPingRejectsPersistentHighLatency(t *testing.T) {
	calls := 0
	got, err := retryMeasuredPing("icmp", func() (int, error) {
		calls++
		return 1200, nil
	})
	if err == nil || !strings.Contains(err.Error(), "latency remains high") {
		t.Fatalf("error = %v, want latency remains high", err)
	}
	if got != -1 || calls != 4 {
		t.Fatalf("got latency=%d calls=%d, want latency=-1 calls=4", got, calls)
	}
}

func TestRetryMeasuredPingStopsOnRetryError(t *testing.T) {
	calls := 0
	got, err := retryMeasuredPing("tcp", func() (int, error) {
		calls++
		if calls == 2 {
			return -1, errors.New("dial failed")
		}
		return 1200, nil
	})
	if err == nil || err.Error() != "dial failed" {
		t.Fatalf("error = %v, want dial failed", err)
	}
	if got != -1 || calls != 2 {
		t.Fatalf("got latency=%d calls=%d, want latency=-1 calls=2", got, calls)
	}
}

func TestBuildProbeResultCalculatesLossFromFailedSamples(t *testing.T) {
	got := buildProbeResult(4, []int{40, 10, 20})
	if !got.OK {
		t.Fatal("expected probe result to be OK")
	}
	if got.RTTMs != 23 {
		t.Fatalf("RTTMs = %d, want 23", got.RTTMs)
	}
	if got.Loss != 25 {
		t.Fatalf("Loss = %d, want 25", got.Loss)
	}
}

func TestBuildProbeResultUsesTenPercentICMPResolution(t *testing.T) {
	got := buildProbeResult(icmpProbeSamplesPerInterval, []int{10, 11, 12, 13, 14, 15, 16, 17, 18})
	if !got.OK {
		t.Fatal("expected probe result to be OK")
	}
	if got.Loss != 10 {
		t.Fatalf("Loss = %d, want 10", got.Loss)
	}
}

func TestICMPBatchIntervalFitsConfiguredTimeout(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		timeout time.Duration
		want    time.Duration
	}{
		{name: "default timeout", count: 10, timeout: 1500 * time.Millisecond, want: 50 * time.Millisecond},
		{name: "minimum timeout", count: 10, timeout: 250 * time.Millisecond, want: 12500 * time.Microsecond},
		{name: "single packet", count: 1, timeout: 250 * time.Millisecond, want: 50 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := icmpBatchInterval(tt.count, tt.timeout); got != tt.want {
				t.Fatalf("icmpBatchInterval() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestProbeAttemptsPerMeasurementUsesOneICMPSample(t *testing.T) {
	if got := probeAttemptsPerMeasurement(pingModeICMP); got != 1 {
		t.Fatalf("ICMP attempts = %d, want 1", got)
	}
	if got := probeAttemptsPerMeasurement(pingModeTCP); got != 4 {
		t.Fatalf("TCP attempts = %d, want 4", got)
	}
}

func TestHybridProbeComponentsKeepTCPAndICMPCadencesSeparate(t *testing.T) {
	if got := scheduledProbeComponentModes(pingModeHybrid, false, true); len(got) != 1 || got[0] != pingModeICMP {
		t.Fatalf("ICMP-only hybrid schedule = %#v, want [icmp]", got)
	}
	got := scheduledProbeComponentModes(pingModeHybrid, true, true)
	if len(got) != 2 || got[0] != pingModeTCP || got[1] != pingModeICMP {
		t.Fatalf("full hybrid schedule = %#v, want [tcp icmp]", got)
	}
	if tcpID, icmpID := probeHistoryID("edge", pingModeHybrid, pingModeTCP), probeHistoryID("edge", pingModeHybrid, pingModeICMP); tcpID == icmpID {
		t.Fatalf("hybrid histories share id %q", tcpID)
	}
}

func TestICMPSamplesAreSpreadAcrossProbeInterval(t *testing.T) {
	if got := icmpSampleInterval(5 * time.Second); got != 500*time.Millisecond {
		t.Fatalf("5 second interval sample spacing = %s, want 500ms", got)
	}
	if got := icmpSampleInterval(20 * time.Second); got != 2*time.Second {
		t.Fatalf("20 second interval sample spacing = %s, want 2s", got)
	}
}

func TestProbeHistorySampleLimitKeepsEqualObservationWindows(t *testing.T) {
	const window = 30 * time.Second
	const interval = 5 * time.Second
	if got := probeHistorySampleLimit(pingModeICMP, window, interval); got != 60 {
		t.Fatalf("ICMP sample limit = %d, want 60", got)
	}
	if got := probeHistorySampleLimit(pingModeTCP, window, interval); got != 6 {
		t.Fatalf("TCP sample limit = %d, want 6", got)
	}
}

func TestBuildProbeResultAllSamplesLost(t *testing.T) {
	got := buildProbeResult(4, nil)
	if got.OK {
		t.Fatal("expected probe result to be failed")
	}
	if got.RTTMs != -1 {
		t.Fatalf("RTTMs = %d, want -1", got.RTTMs)
	}
	if got.Loss != 100 {
		t.Fatalf("Loss = %d, want 100", got.Loss)
	}
}

func TestCombineHybridProbeResultUsesTCPRTTAndICMPLoss(t *testing.T) {
	got := combineHybridProbeResult(
		ProbeResult{RTTMs: 42, Loss: 100, OK: true},
		ProbeResult{RTTMs: 18, Loss: 25, OK: true},
	)
	if !got.OK || got.RTTMs != 42 || got.Loss != 25 {
		t.Fatalf("hybrid result = %+v, want TCP RTT 42 and ICMP loss 25", got)
	}
}

func TestRollingProbeHistoryKeepsHybridLossIndependentFromTCPStatus(t *testing.T) {
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	history.add(now, "hybrid\x00example.com:443", ProbeResult{RTTMs: -1, Loss: 0, OK: false}, 2)
	history.add(now.Add(20*time.Second), "hybrid\x00example.com:443", ProbeResult{RTTMs: 30, Loss: 0, OK: true}, 2)

	got := history.snapshot(now.Add(20*time.Second), 2*time.Minute, 2)
	if !got.OK || got.RTTMs != 30 || got.Loss != 0 {
		t.Fatalf("hybrid rolling result = %+v, want RTT 30 and loss 0", got)
	}
}

func TestRollingProbeHistoryAveragesTwoMinuteWindow(t *testing.T) {
	const interval = 20 * time.Second
	const window = 2 * time.Minute
	const samples = 6
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	results := []ProbeResult{
		{RTTMs: 10, Loss: 0, OK: true},
		{RTTMs: 20, Loss: 0, OK: true},
		{RTTMs: -1, Loss: 100, OK: false},
		{RTTMs: 30, Loss: 0, OK: true},
		{RTTMs: 100, Loss: 0, OK: true},
		{RTTMs: -1, Loss: 100, OK: false},
	}
	for i, result := range results {
		history.add(now.Add(time.Duration(i)*interval), "example.com", result, samples)
	}

	got := history.snapshot(now.Add(5*interval), window, samples)
	if !got.OK {
		t.Fatal("expected rolling probe result to be OK")
	}
	if got.RTTMs != 40 {
		t.Fatalf("RTTMs = %d, want 40", got.RTTMs)
	}
	if got.Loss != 33 {
		t.Fatalf("Loss = %d, want 33", got.Loss)
	}
}

func TestRollingProbeHistoryAverageReflectsLatencySpike(t *testing.T) {
	const samples = 6
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	for i := 0; i < samples; i++ {
		rtt := 20
		if i == samples-1 {
			rtt = 200
		}
		history.add(now.Add(time.Duration(i)*20*time.Second), "example.com", ProbeResult{RTTMs: rtt, OK: true}, samples)
	}

	got := history.snapshot(now.Add(100*time.Second), 2*time.Minute, samples)
	if !got.OK || got.RTTMs != 50 || got.Loss != 0 {
		t.Fatalf("rolling result = %+v, want RTT 50 and loss 0", got)
	}
}

func TestRollingProbeHistoryPreservesPartialPacketLoss(t *testing.T) {
	const samples = 4
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	results := []ProbeResult{
		{RTTMs: 10, Loss: 0, OK: true},
		{RTTMs: 20, Loss: 25, OK: true},
		{RTTMs: 30, Loss: 50, OK: true},
		{RTTMs: 40, Loss: 0, OK: true},
	}
	for i, result := range results {
		history.add(now.Add(time.Duration(i)*20*time.Second), "example.com", result, samples)
	}

	got := history.snapshot(now.Add(60*time.Second), 2*time.Minute, samples)
	if !got.OK {
		t.Fatal("expected partial packet loss to keep a valid latency result")
	}
	if got.Loss != 19 {
		t.Fatalf("Loss = %d, want 19", got.Loss)
	}
}

func TestRollingProbeHistoryReportsOneLostUniformICMPSample(t *testing.T) {
	const samples = 60
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	for i := 0; i < samples; i++ {
		result := ProbeResult{RTTMs: 20, Loss: 0, OK: true}
		if i == 30 {
			result = ProbeResult{RTTMs: -1, Loss: 100, OK: false}
		}
		history.add(now.Add(time.Duration(i)*500*time.Millisecond), "example.com", result, samples)
	}

	got := history.snapshot(now.Add(29500*time.Millisecond), 30*time.Second, samples)
	if got.Loss != 2 {
		t.Fatalf("Loss = %d, want 2", got.Loss)
	}
}

func TestRollingProbeHistoryKeepsSixSamples(t *testing.T) {
	const interval = 20 * time.Second
	const window = 2 * time.Minute
	const samples = 6
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	history.add(now, "example.com", ProbeResult{RTTMs: -1, Loss: 100, OK: false}, samples)
	for i := 1; i <= 6; i++ {
		history.add(now.Add(time.Duration(i)*interval), "example.com", ProbeResult{RTTMs: i * 10, OK: true}, samples)
	}

	got := history.snapshot(now.Add(6*interval), window, samples)
	if got.Loss != 0 {
		t.Fatalf("Loss = %d, want 0", got.Loss)
	}
	if len(history.samples) != samples {
		t.Fatalf("samples = %d, want %d", len(history.samples), samples)
	}
}

func TestRollingProbeHistoryUsesAvailableSamplesBeforeWindowIsFull(t *testing.T) {
	const interval = 20 * time.Second
	const window = 2 * time.Minute
	const samples = 6
	now := time.Unix(1000, 0)
	history := rollingProbeHistory{}
	history.add(now, "example.com", ProbeResult{RTTMs: 40, OK: true}, samples)
	history.add(now.Add(interval), "example.com", ProbeResult{RTTMs: -1, Loss: 100, OK: false}, samples)

	got := history.snapshot(now.Add(interval), window, samples)
	if !got.OK {
		t.Fatal("expected available successful sample to produce an OK result")
	}
	if got.RTTMs != 40 {
		t.Fatalf("RTTMs = %d, want 40", got.RTTMs)
	}
	if got.Loss != 50 {
		t.Fatalf("Loss = %d, want 50", got.Loss)
	}
}
