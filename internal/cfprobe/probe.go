package cfprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ping "github.com/prometheus-community/pro-bing"
)

const (
	defaultPingTimeout      = 1500 * time.Millisecond
	highLatencyThresholdMS  = 1000
	pingHighLatencyRetries  = 3
	retryDropThresholdTCPMS = 800
	defaultTaskPingTCPPort  = 80
	defaultMetricsTCPPort   = 80
	defaultDNSCacheTTL      = 30 * time.Minute
)

type dnsCacheEntry struct {
	ip        string
	expiresAt time.Time
}

var (
	dnsCacheMu  sync.RWMutex
	dnsCache    = map[string]dnsCacheEntry{}
	dnsCacheTTL = defaultDNSCacheTTL
	lookupIP    = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		resolver := net.Resolver{}
		return resolver.LookupIPAddr(ctx, host)
	}
)

func setDNSCacheTTL(seconds int) {
	ttl := time.Duration(seconds) * time.Second
	if ttl < 30*time.Second || ttl > 24*time.Hour {
		ttl = defaultDNSCacheTTL
	}
	dnsCacheMu.Lock()
	dnsCacheTTL = ttl
	dnsCache = map[string]dnsCacheEntry{}
	dnsCacheMu.Unlock()
}

func splitProbeTarget(target string, defaultPort int) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, errors.New("empty target")
	}
	host := target
	port := defaultPort
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		parsed, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, err
		}
		port = parsed
	} else if strings.Count(target, ":") == 1 {
		before, after, ok := strings.Cut(target, ":")
		if ok && before != "" && after != "" {
			parsed, err := strconv.Atoi(after)
			if err != nil {
				return "", 0, err
			}
			host = before
			port = parsed
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.HasPrefix(host, "-") {
		return "", 0, errors.New("invalid host")
	}
	if port < 1 || port > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return host, port, nil
}

func resolveFirstIP(ctx context.Context, host string) (string, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	key := strings.ToLower(host)
	now := time.Now()
	dnsCacheMu.RLock()
	ttl := dnsCacheTTL
	if entry, ok := dnsCache[key]; ok && now.Before(entry.expiresAt) {
		dnsCacheMu.RUnlock()
		return entry.ip, nil
	}
	dnsCacheMu.RUnlock()

	addrs, err := lookupIP(ctx, host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if addr.IP != nil {
			ip := addr.IP.String()
			dnsCacheMu.Lock()
			dnsCache[key] = dnsCacheEntry{ip: ip, expiresAt: now.Add(ttl)}
			dnsCacheMu.Unlock()
			return ip, nil
		}
	}
	return "", errors.New("no address")
}

func tcpPing(target string, defaultPort int, timeout time.Duration) (int, error) {
	host, port, err := splitProbeTarget(target, defaultPort)
	if err != nil {
		return -1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ip, err := resolveFirstIP(ctx, host)
	if err != nil {
		return -1, err
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

func httpPing(target string, timeout time.Duration) (int, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return -1, errors.New("empty target")
	}
	if strings.Contains(raw, ":") && !strings.Contains(raw, "[") {
		if ip := net.ParseIP(raw); ip != nil && ip.To4() == nil {
			raw = "[" + raw + "]"
		}
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return -1, err
	}
	targetHost := strings.Trim(parsed.Hostname(), "[]")
	if targetHost == "" {
		return -1, errors.New("empty host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	targetIP, err := resolveFirstIP(ctx, targetHost)
	cancel()
	if err != nil {
		return -1, err
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip := targetIP
			if strings.Trim(host, "[]") != targetHost {
				resolved, err := resolveFirstIP(ctx, host)
				if err != nil {
					return nil, err
				}
				ip = resolved
			}
			return net.DialTimeout(network, net.JoinHostPort(ip, port), timeout)
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Timeout: timeout, Transport: transport}
	start := time.Now()
	resp, err := client.Get(parsed.String())
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return ms, nil
	}
	return ms, fmt.Errorf("http status %d", resp.StatusCode)
}

func resolveICMPTarget(target string, timeout time.Duration) (string, error) {
	host, _, err := splitProbeTarget(target, defaultTaskPingTCPPort)
	if err != nil {
		host = strings.Trim(strings.TrimSpace(target), "[]")
	}
	if host == "" {
		return "", errors.New("empty target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ip, err := resolveFirstIP(ctx, host)
	defer cancel()
	if err != nil {
		return "", err
	}
	return ip, nil
}

func icmpBatchInterval(count int, timeout time.Duration) time.Duration {
	const preferred = 50 * time.Millisecond
	if count <= 1 || timeout <= 0 {
		return preferred
	}
	interval := timeout / time.Duration(count*2)
	if interval > preferred {
		return preferred
	}
	if interval < time.Millisecond {
		return time.Millisecond
	}
	return interval
}

func probeAttemptsPerRun(kind string) int {
	if kind == pingModeICMP {
		return icmpProbePacketsPerRun
	}
	return tcpProbeAttemptsPerRun
}

func measureICMPProbe(target string, count int, timeout time.Duration) (ProbeResult, error) {
	if count < 1 {
		count = 1
	}
	ip, err := resolveICMPTarget(target, timeout)
	if err != nil {
		return ProbeResult{RTTMs: -1, Loss: 100, OK: false}, err
	}

	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return ProbeResult{RTTMs: -1, Loss: 100, OK: false}, err
	}
	pinger.Count = count
	pinger.Timeout = timeout
	pinger.Interval = icmpBatchInterval(count, timeout)
	pinger.SetPrivileged(true)
	if err := pinger.Run(); err != nil {
		return ProbeResult{RTTMs: -1, Loss: 100, OK: false}, err
	}
	stats := pinger.Statistics()
	values := make([]int, 0, len(stats.Rtts))
	for _, rtt := range stats.Rtts {
		ms := int(rtt.Milliseconds())
		if ms < 1 {
			ms = 1
		}
		values = append(values, ms)
	}
	result := buildProbeResult(count, values)
	if !result.OK {
		return result, errors.New("no packets received")
	}
	return result, nil
}

func icmpPing(target string, timeout time.Duration) (int, error) {
	result, err := measureICMPProbe(target, 1, timeout)
	if err != nil {
		return -1, err
	}
	return result.RTTMs, nil
}

func measureProbe(kind, target string, count, defaultPort int, timeout time.Duration, log logger) ProbeResult {
	if strings.TrimSpace(target) == "" {
		return ProbeResult{RTTMs: -1, Loss: 100, OK: false}
	}
	if kind != pingModeICMP {
		kind = pingModeTCP
	}
	if count < 1 {
		count = 4
	}
	if defaultPort <= 0 {
		defaultPort = defaultMetricsTCPPort
	}
	if timeout <= 0 {
		timeout = defaultPingTimeout
	}
	if kind == pingModeICMP {
		result, err := measureICMPProbe(target, count, timeout)
		if err != nil {
			log.debugf("probe %s failed target=%s err=%v", kind, target, err)
		}
		return result
	}
	ok := 0
	values := make([]int, 0, count)
	for i := 0; i < count; i++ {
		ms, err := tcpPing(target, defaultPort, timeout)
		if err == nil {
			ok++
			values = append(values, ms)
		} else {
			log.debugf("probe %s failed target=%s err=%v", kind, target, err)
		}
	}
	return buildProbeResult(count, values[:ok])
}

func probeHistoryKey(kind, target string) string {
	if kind != pingModeICMP {
		kind = pingModeTCP
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	return kind + "\x00" + target
}

func buildProbeResult(count int, values []int) ProbeResult {
	if count < 1 {
		count = 1
	}
	ok := len(values)
	if ok == 0 {
		return ProbeResult{RTTMs: -1, Loss: 100, OK: false}
	}
	return ProbeResult{RTTMs: medianInt(values), Loss: (count - ok) * 100 / count, OK: true}
}

func medianInt(values []int) int {
	sort.Ints(values)
	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + values[len(values)/2]) / 2
	}
	return median
}

func measurePing(kind, target string, timeout time.Duration) (int, error) {
	return measurePingWithRetries(kind, target, timeout, defaultTaskPingTCPPort)
}

func measurePingWithRetries(kind, target string, timeout time.Duration, defaultPort int) (int, error) {
	return retryMeasuredPing(kind, func() (int, error) {
		switch kind {
		case "icmp":
			return icmpPing(target, timeout)
		case "tcp":
			return tcpPing(target, defaultPort, timeout)
		case "http":
			return httpPing(target, timeout)
		default:
			return -1, fmt.Errorf("unsupported ping type %q", kind)
		}
	})
}

func retryMeasuredPing(kind string, measure func() (int, error)) (int, error) {
	latency, err := measure()
	if err != nil {
		return -1, err
	}
	firstLatency := latency
	if latency <= highLatencyThresholdMS || pingHighLatencyRetries <= 0 {
		return latency, nil
	}
	for i := 0; i < pingHighLatencyRetries; i++ {
		second, err := measure()
		if err != nil {
			return -1, err
		}
		if second <= highLatencyThresholdMS {
			if kind == "tcp" && firstLatency-second > retryDropThresholdTCPMS {
				return -1, errors.New("suspicious retransmission detected in tcp handshake")
			}
			return second, nil
		}
		if i == pingHighLatencyRetries-1 {
			return -1, errors.New("latency remains high after retries")
		}
	}
	return latency, nil
}
