package cfprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Agent struct {
	cfg     Config
	cfgMu   sync.RWMutex
	paths   Paths
	log     logger
	version string
	ctx     context.Context

	mu         sync.RWMutex
	probes     ProbeSnapshot
	basic      BasicStats
	basicAt    time.Time
	fullAt     time.Time
	prevNet    NetBytes
	prevTime   time.Time
	prevDisk   DiskIOCounters
	prevDiskAt time.Time
	diskIO     DiskIOStats
	traffic    trafficState
	clock      calibratedClock

	samples                  []metricSample
	lastSample               time.Time
	lastSampleProbeVersion   uint64
	lastReport               time.Time
	lastPost                 time.Time
	lastPostAttempt          time.Time
	lastConfigStateReportAt  time.Time
	lastConfigStateReportMD5 string
	updateMu                 sync.Mutex
	reporter                 *reportTransport
	wake                     chan struct{}
	networkWake              chan struct{}
	remoteConfig             chan remoteConfigRequest
	wssRuntimeMu             sync.Mutex
	wssRuntimeDisabledAt     time.Time
	wssRuntimeDisabledReason string
}

const (
	agentWSSModeDisabled      = "disabled"
	agentWSSScheduleDisabled  = "wss_disabled"
	configStateReportInterval = time.Minute
	agentWSSModeHeader        = "X-Agent-Wss-Mode"
	agentWSSReasonHeader      = "X-Agent-Wss-Reason"
	agentWSSModeActive        = "active"
	agentWSSModeInactive      = "inactive"
	agentWSSScheduleInactive  = "wss_schedule_inactive"
	agentWSSScheduleEmpty     = "wss_schedule_empty"
)

type timedProbeResult struct {
	at     time.Time
	result ProbeResult
}

type rollingProbeHistory struct {
	target  string
	samples []timedProbeResult
}

type metricSample struct {
	at      time.Time
	metrics map[string]any
}

type reportSendResult struct {
	ok      bool
	viaWSS  bool
	viaPOST bool
}

type remoteConfigRequest struct {
	body            []byte
	headers         http.Header
	allowMissingMD5 bool
	done            chan error
}

func (h *rollingProbeHistory) add(now time.Time, target string, result ProbeResult, maxSamples int) {
	target = strings.TrimSpace(target)
	if target == "" {
		h.target = ""
		h.samples = nil
		return
	}
	if h.target != target {
		h.target = target
		h.samples = nil
	}
	h.samples = append(h.samples, timedProbeResult{at: now, result: result})
	if maxSamples < 1 {
		maxSamples = 1
	}
	if len(h.samples) > maxSamples {
		h.samples = h.samples[len(h.samples)-maxSamples:]
	}
}

func (h rollingProbeHistory) snapshot(now time.Time, window time.Duration, maxSamples int) ProbeResult {
	if len(h.samples) == 0 {
		return ProbeResult{}
	}

	if window <= 0 {
		window = time.Minute
	}
	cutoff := now.Add(-window)
	values := make([]int, 0, len(h.samples))
	for _, sample := range h.samples {
		if sample.at.Before(cutoff) || !sample.result.OK || sample.result.RTTMs < 0 {
			continue
		}
		values = append(values, sample.result.RTTMs)
	}

	lossSamples := h.samples
	if maxSamples > 0 && len(lossSamples) > maxSamples {
		lossSamples = lossSamples[len(lossSamples)-maxSamples:]
	}
	lost := 0
	for _, sample := range lossSamples {
		if !sample.result.OK {
			lost++
		}
	}
	loss := lost * 100 / len(lossSamples)

	if len(values) == 0 {
		return ProbeResult{RTTMs: -1, Loss: loss, OK: false}
	}
	return ProbeResult{RTTMs: medianInt(values), Loss: loss, OK: true}
}

func Run(configFile string, debug bool, version string) error {
	paths := defaultPaths()
	if configFile != "" {
		paths.ConfigFile = configFile
		paths.ConfigDir = filepath.Dir(configFile)
	}
	releaseLock, err := acquireInstanceLock(paths)
	if err != nil {
		return err
	}
	defer releaseLock()

	cfg, err := readConfig(paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("读取配置失败 %s: %w", paths.ConfigFile, err)
	}
	if cfg.ServerID == "" || cfg.Secret == "" || cfg.WorkerURL == "" {
		return errors.New("配置缺失: SERVER_ID/SECRET/WORKER_URL 不能为空")
	}
	normalizeConfigIntervals(&cfg)
	legacyTrafficFile := paths.TrafficFile
	if stateDir := resolveStateDir(cfg.StateDir, paths.ConfigFile); stateDir != "" {
		paths.TrafficFile = filepath.Join(stateDir, "traffic.dat")
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			return fmt.Errorf("create state directory %s failed: %w", stateDir, err)
		}
		if legacyTrafficFile != paths.TrafficFile {
			migrateTrafficState(legacyTrafficFile, paths.TrafficFile)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()

	a := &Agent{
		cfg:          cfg,
		paths:        paths,
		log:          newLogger(debug),
		version:      version,
		ctx:          ctx,
		prevNet:      readNetBytes(cfg.Interface),
		prevTime:     time.Now(),
		traffic:      readTrafficState(paths.TrafficFile),
		wake:         make(chan struct{}, 1),
		networkWake:  make(chan struct{}, 1),
		remoteConfig: make(chan remoteConfigRequest, 4),
	}
	setDNSCacheTTL(cfg.DNSCacheSeconds)
	a.reporter = newReportTransport(a)
	a.basic = collectBasicStats()
	a.basicAt = time.Now()

	a.log.info("CF-Server-Monitor Go Probe started version=%s platform=%s config=%s", version, platformName(), paths.ConfigFile)
	a.log.debugf("config id=%s url=%s report_interval=%ds collect_interval=%ds reset_day=%d connection_mode=%s probes=%d interface=%s auto_update=%v",
		cfg.ServerID, cfg.WorkerURL, cfg.ReportInterval, cfg.CollectInterval, cfg.ResetDay, cfg.ConnectionMode, len(cfg.Probes), firstNonEmpty(cfg.Interface, "auto"), cfg.AutoUpdate)

	go a.networkWorker(ctx)
	if a.usesWSS() {
		a.reporter.start(ctx)
	} else {
		a.log.info("WSS disabled connection_mode=http")
	}
	if cfg.AutoUpdate {
		go a.autoUpdateWorker(ctx)
	} else {
		a.log.info("auto update disabled: local AUTO_UPDATE=0")
	}
	return a.loop(ctx)
}

func resolveStateDir(configured, configFile string) string {
	if value := strings.TrimSpace(configured); value != "" {
		return filepath.Clean(value)
	}
	if value := strings.TrimSpace(os.Getenv("CFSM_STATE_DIR")); value != "" {
		return filepath.Clean(value)
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(filepath.Dir(configFile), "state")
	}
	name := filepath.Base(filepath.Dir(configFile))
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = serviceNameDefault
	}
	return filepath.Join("/var/lib", name)
}

func migrateTrafficState(source, target string) {
	if source == "" || target == "" || source == target {
		return
	}
	if _, err := os.Stat(target); err == nil {
		return
	}
	data, err := os.ReadFile(source)
	if err != nil || len(data) == 0 {
		return
	}
	_ = os.WriteFile(target, data, 0o600)
}

func (a *Agent) loop(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			a.log.info("probe stopped")
			return nil
		case <-timer.C:
			a.tick()
			resetTimer(timer, a.tickInterval())
		case <-a.wake:
			a.tick()
			resetTimer(timer, a.tickInterval())
		case req := <-a.remoteConfig:
			err := a.applyRemoteConfigWithOptions(req.body, req.headers, req.allowMissingMD5)
			req.done <- err
			resetTimer(timer, a.tickInterval())
		}
	}
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if d <= 0 {
		d = time.Second
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func (a *Agent) wakeTick() {
	if a == nil || a.wake == nil {
		return
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *Agent) tickInterval() time.Duration {
	cfg := a.configSnapshot()
	active := a.currentWSSReportIntervalForConfig(cfg)
	if collect := effectiveCollectInterval(cfg); collect > 0 {
		active = durationGCD(active, collect)
	}
	if active <= 0 {
		return time.Second
	}
	return active
}

func (a *Agent) effectiveCollectInterval() time.Duration {
	return effectiveCollectInterval(a.configSnapshot())
}

func effectiveCollectInterval(cfg Config) time.Duration {
	collect := time.Duration(cfg.CollectInterval) * time.Second
	if collect < 0 {
		collect = 0
	}
	return collect
}

func (a *Agent) currentWSSReportInterval() time.Duration {
	return a.currentWSSReportIntervalForConfig(a.configSnapshot())
}

func (a *Agent) currentWSSReportIntervalForConfig(cfg Config) time.Duration {
	if a.reporter != nil && a.usesWSSConfig(cfg) {
		fallback := time.Duration(defaultWSSReportIntervalSec) * time.Second
		return a.reporter.reportInterval(fallback)
	}
	reportInterval := time.Duration(cfg.ReportInterval) * time.Second
	if reportInterval < time.Second {
		return time.Duration(defaultReportIntervalSec) * time.Second
	}
	return reportInterval
}

func (a *Agent) persistentUsesWSS() bool {
	return persistentUsesWSSConfig(a.configSnapshot())
}

func persistentUsesWSSConfig(cfg Config) bool {
	mode, err := normalizeConnectionMode(cfg.ConnectionMode)
	if err != nil {
		mode = connectionModeAuto
	}
	return mode != connectionModeHTTP
}

func (a *Agent) wssRuntimeDisabled() (bool, string) {
	if a == nil {
		return false, ""
	}
	a.wssRuntimeMu.Lock()
	defer a.wssRuntimeMu.Unlock()
	return !a.wssRuntimeDisabledAt.IsZero(), a.wssRuntimeDisabledReason
}

func (a *Agent) usesWSS() bool {
	return a.usesWSSConfig(a.configSnapshot())
}

func (a *Agent) usesWSSConfig(cfg Config) bool {
	if !persistentUsesWSSConfig(cfg) {
		return false
	}
	disabled, _ := a.wssRuntimeDisabled()
	return !disabled
}

func (a *Agent) configSnapshot() Config {
	if a == nil {
		return Config{}
	}
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

func (a *Agent) setConfig(cfg Config) {
	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgMu.Unlock()
	setDNSCacheTTL(cfg.DNSCacheSeconds)
	if a.networkWake != nil {
		select {
		case a.networkWake <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) disableWSSRuntime(reason string) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = agentWSSScheduleInactive
	}
	now := time.Now()
	a.wssRuntimeMu.Lock()
	alreadyDisabled := !a.wssRuntimeDisabledAt.IsZero() && a.wssRuntimeDisabledReason == reason
	if alreadyDisabled {
		a.wssRuntimeMu.Unlock()
		return
	}
	a.wssRuntimeDisabledAt = now
	a.wssRuntimeDisabledReason = reason
	a.wssRuntimeMu.Unlock()
	a.log.info("WSS temporarily disabled reason=%s; using POST report", reason)
	if a.reporter != nil {
		a.reporter.stop(reason)
	}
	a.wakeTick()
}

func (a *Agent) clearWSSRuntimeDisabled(reason string) {
	a.wssRuntimeMu.Lock()
	wasDisabled := !a.wssRuntimeDisabledAt.IsZero()
	a.wssRuntimeDisabledAt = time.Time{}
	a.wssRuntimeDisabledReason = ""
	a.wssRuntimeMu.Unlock()
	if !wasDisabled {
		return
	}
	if reason == "" {
		reason = "server_active"
	}
	a.log.info("WSS temporary disable cleared reason=%s", reason)
	a.syncReportTransport()
	a.wakeTick()
}

func (a *Agent) handleWSSRuntimeHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(headers.Get(agentWSSModeHeader)))
	reason := strings.ToLower(strings.TrimSpace(headers.Get(agentWSSReasonHeader)))
	switch mode {
	case agentWSSModeActive:
		a.clearWSSRuntimeDisabled(reason)
	case agentWSSModeInactive:
		if isWSSScheduleInactiveReason(reason) {
			a.disableWSSRuntime(reason)
		}
	case agentWSSModeDisabled:
		if isWSSScheduleInactiveReason(reason) {
			a.disableWSSRuntime(reason)
		}
	}
}

func (a *Agent) tick() {
	now := time.Now()
	cfg := a.configSnapshot()
	reportInterval := time.Duration(cfg.ReportInterval) * time.Second
	if reportInterval < time.Second {
		reportInterval = time.Duration(defaultReportIntervalSec) * time.Second
	}
	wssEnabled := a.usesWSSConfig(cfg)
	wssConnected := wssEnabled && a.reporter != nil && a.reporter.connected()
	shouldWSSReport := wssConnected && (a.lastReport.IsZero() || now.Sub(a.lastReport) >= a.currentWSSReportIntervalForConfig(cfg))
	postDue := !wssConnected && (a.lastPost.IsZero() || now.Sub(a.lastPost) >= reportInterval)
	postAllowed := !wssEnabled || a.reporter == nil || a.reporter.postFallbackAllowed()
	if postDue && !postAllowed && wssEnabled && a.reporter != nil {
		a.reporter.logPostFallbackDelayed()
	}
	shouldPostReport := postDue && postAllowed && a.postAttemptAllowed(now, reportInterval)
	shouldSample := false
	if collectInterval := effectiveCollectInterval(cfg); collectInterval > 0 {
		shouldSample = a.lastSample.IsZero() || now.Sub(a.lastSample) >= collectInterval
	}
	if !shouldWSSReport && !shouldPostReport && !shouldSample {
		return
	}
	reportDue := shouldWSSReport || shouldPostReport
	fullDue := reportDue && (a.fullAt.IsZero() || now.Sub(a.fullAt) >= reportInterval)
	if fullDue {
		a.basic = collectBasicStats()
		a.basicAt = now
	} else {
		a.refreshRealtimeBasicStats()
	}
	netNow := readNetBytes(cfg.Interface)
	dt := now.Sub(a.prevTime).Seconds()
	if dt <= 0 {
		dt = float64(cfg.ReportInterval)
	}
	rxDelta := uint64(0)
	txDelta := uint64(0)
	if netNow.RX >= a.prevNet.RX {
		rxDelta = netNow.RX - a.prevNet.RX
	}
	if netNow.TX >= a.prevNet.TX {
		txDelta = netNow.TX - a.prevNet.TX
	}
	rxSpeed := uint64(float64(rxDelta) / dt)
	txSpeed := uint64(float64(txDelta) / dt)
	a.prevNet = netNow
	a.prevTime = now

	cpu := "0.00"
	if usage, ok := readCPUPercent(); ok {
		cpu = cpuPercentString(usage)
	}

	trafficBoundaryChanged := advanceTrafficState(&a.traffic, netNow, now, cfg.ResetDay, cfg.Interface)
	if fullDue || trafficBoundaryChanged {
		if err := writeTrafficState(a.paths.TrafficFile, a.traffic); err != nil {
			a.log.warnf("persist traffic state failed: %v", err)
		}
	}
	if fullDue {
		a.diskIO = a.sampleDiskIO(now)
		a.fullAt = now
	}
	m := a.buildMetrics(
		cfg,
		cpu,
		netNow,
		rxSpeed,
		txSpeed,
		a.traffic.RXPeriod,
		a.traffic.TXPeriod,
		a.traffic.RXDaily,
		a.traffic.TXDaily,
		now,
		a.diskIO,
	)
	if shouldSample {
		includeProbes := m.probeVersion > 0 && m.probeVersion != a.lastSampleProbeVersion
		a.samples = append(a.samples, metricSample{
			at:      now,
			metrics: sampleMetricsToMap(m, includeProbes),
		})
		if includeProbes {
			a.lastSampleProbeVersion = m.probeVersion
		}
		a.lastSample = now
	}
	if reportDue && m.probeVersion > 0 && m.probeVersion != a.lastSampleProbeVersion && len(a.samples) > 0 {
		a.samples[len(a.samples)-1].metrics["probes"] = m.Probes
		a.lastSampleProbeVersion = m.probeVersion
	}
	if shouldWSSReport || shouldPostReport {
		if result := a.sendReport(cfg, m, shouldWSSReport, shouldPostReport, reportInterval); result.ok {
			if len(a.samples) == 0 && m.probeVersion > 0 {
				a.lastSampleProbeVersion = m.probeVersion
			}
			if result.viaWSS {
				a.lastReport = now
				a.lastPost = now
			} else if result.viaPOST {
				a.lastPost = now
			}
			a.samples = nil
		}
	}
}

func (a *Agent) refreshRealtimeBasicStats() {
	if mem, ok := readMemoryStats(); ok {
		a.basic.MemTotalMB = mem.MemTotalMB
		a.basic.MemUsedMB = mem.MemUsedMB
		a.basic.SwapTotalMB = mem.SwapTotalMB
		a.basic.SwapUsedMB = mem.SwapUsedMB
	}
	if total, used, ok := readDiskUsageStats(); ok {
		a.basic.DiskTotalMB = total
		a.basic.DiskUsedMB = used
	}
}

func (a *Agent) sampleDiskIO(now time.Time) DiskIOStats {
	current := readDiskIOCounters(a.basic.DiskDevices)
	if a.prevDiskAt.IsZero() {
		a.prevDisk = current
		a.prevDiskAt = now
		return DiskIOStats{}
	}
	elapsed := now.Sub(a.prevDiskAt).Seconds()
	stats := diskIOStatsFromCounters(a.prevDisk, current, elapsed)
	a.prevDisk = current
	a.prevDiskAt = now
	return stats
}

func (a *Agent) buildMetrics(cfg Config, cpu string, netNow NetBytes, rxSpeed, txSpeed, rxMonthly, txMonthly, rxDaily, txDaily uint64, now time.Time, diskIO DiskIOStats) Metrics {
	a.mu.RLock()
	probes := a.probes
	a.mu.RUnlock()
	b := a.basic
	probeMetrics := make(map[string]ProbeMetric, len(cfg.Probes))
	for _, node := range cfg.Probes {
		result := probes.Results[node.ID]
		metric := ProbeMetric{Loss: 100}
		if result.Loss >= 0 && result.Loss <= 100 {
			metric.Loss = result.Loss
		}
		if result.OK && result.RTTMs >= 0 {
			metric.RTT = result.RTTMs
		}
		probeMetrics[node.ID] = metric
	}
	return Metrics{
		CPU:          cpu,
		RAMTotal:     uintString(b.MemTotalMB),
		RAMUsed:      uintString(b.MemUsedMB),
		SwapTotal:    uintString(b.SwapTotalMB),
		SwapUsed:     uintString(b.SwapUsedMB),
		DiskTotal:    uintString(b.DiskTotalMB),
		DiskUsed:     uintString(b.DiskUsedMB),
		Disk:         diskIO,
		LoadAvg:      firstNonEmpty(b.LoadAvg, "0 0 0"),
		BootTime:     strconv.FormatInt(b.BootTimeMS, 10),
		NetRX:        uintString(netNow.RX),
		NetTX:        uintString(netNow.TX),
		NetRXMonthly: uintString(rxMonthly),
		NetTXMonthly: uintString(txMonthly),
		NetRXDaily:   uintString(rxDaily),
		NetTXDaily:   uintString(txDaily),
		DayStart:     strconv.FormatInt(startOfLocalDay(now).Unix(), 10),
		DayEnd:       strconv.FormatInt(endOfLocalDay(now).Unix(), 10),
		NetInSpeed:   uintString(rxSpeed),
		NetOutSpeed:  uintString(txSpeed),
		OS:           firstNonEmpty(b.OSName, runtime.GOOS),
		Arch:         firstNonEmpty(b.Arch, fallbackArch()),
		Kernel:       b.Kernel,
		CPUInfo:      firstNonEmpty(b.CPUInfo, fallbackArch()),
		CPUCores:     intString(b.CPUCores),
		GPUInfo:      b.GPUInfo,
		Processes:    intString(b.Processes),
		TCPConn:      intString(b.TCPConn),
		UDPConn:      intString(b.UDPConn),
		IPv4:         firstNonEmpty(probes.IPv4, "0"),
		IPv6:         firstNonEmpty(probes.IPv6, "0"),
		Probes:       probeMetrics,
		probeVersion: probes.Version,
	}
}

func (a *Agent) report(m Metrics) {
	cfg := a.configSnapshot()
	reportAt := time.Now()
	body, sampleCount, err := a.buildReportBodyForConfig(cfg, m, reportAt)
	if err != nil {
		a.log.warnf("marshal payload failed: %v", err)
		return
	}
	a.logMetricsSummary(m)
	_, _ = a.postReportBody(cfg, body, sampleCount, false)
}

func (a *Agent) sendReport(cfg Config, m Metrics, preferWSS, allowPOST bool, reportInterval time.Duration) reportSendResult {
	reportAt := time.Now()
	body, sampleCount, err := a.buildReportBodyForConfig(cfg, m, reportAt)
	if err != nil {
		a.log.warnf("marshal payload failed: %v", err)
		return reportSendResult{}
	}
	a.logMetricsSummary(m)
	wssFailed := false
	if preferWSS && a.reporter != nil {
		a.log.debugf("WSS report attempt url=%s payload_bytes=%d samples=%d", a.reporter.url(), len(body), sampleCount)
		if a.reporter.send(body) {
			return reportSendResult{ok: true, viaWSS: true}
		}
		wssFailed = true
	}
	if !allowPOST && !wssFailed {
		return reportSendResult{}
	}
	if preferWSS && a.reporter != nil && !a.reporter.postFallbackAllowed() {
		a.reporter.logPostFallbackDelayed()
		return reportSendResult{}
	}
	if !a.postAttemptAllowed(reportAt, reportInterval) {
		return reportSendResult{}
	}
	a.lastPostAttempt = reportAt
	statusCode, err := a.postReportBody(cfg, body, sampleCount, preferWSS)
	if isAuthConfigHTTPStatus(statusCode) && a.reporter != nil {
		a.reporter.delayProtocol(fmt.Sprintf("POST fallback http=%d", statusCode))
	}
	if err != nil || statusCode < 200 || statusCode >= 300 {
		return reportSendResult{}
	}
	return reportSendResult{ok: true, viaPOST: true}
}

func (a *Agent) postAttemptAllowed(now time.Time, reportInterval time.Duration) bool {
	if a == nil || a.lastPostAttempt.IsZero() {
		return true
	}
	if reportInterval < time.Second {
		reportInterval = time.Duration(defaultReportIntervalSec) * time.Second
	}
	return now.Sub(a.lastPostAttempt) >= reportInterval
}

func (a *Agent) buildReportBody(m Metrics, reportAt time.Time) ([]byte, int, error) {
	return a.buildReportBodyForConfig(a.configSnapshot(), m, reportAt)
}

func (a *Agent) buildReportBodyForConfig(cfg Config, m Metrics, reportAt time.Time) ([]byte, int, error) {
	payload := map[string]any{
		"id":               cfg.ServerID,
		"secret":           cfg.Secret,
		"time":             a.clock.snapshot(reportAt),
		"metrics":          a.metricsForReport(m, reportAt),
		"collect_interval": cfg.CollectInterval,
		"report_interval":  cfg.ReportInterval,
	}
	if a.shouldReportConfigState(firstNonEmpty(cfg.ConfigMD5, "none"), reportAt) {
		payload["config_schema"] = configSchemaVersion
		payload["config_md5"] = firstNonEmpty(cfg.ConfigMD5, "none")
	}
	if len(a.samples) > 0 {
		payload["samples"] = a.samplesForReport()
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	return body, len(a.samples), nil
}

func (a *Agent) shouldReportConfigState(configMD5 string, reportAt time.Time) bool {
	if a.lastConfigStateReportAt.IsZero() ||
		configMD5 != a.lastConfigStateReportMD5 ||
		reportAt.Sub(a.lastConfigStateReportAt) >= configStateReportInterval {
		a.lastConfigStateReportAt = reportAt
		a.lastConfigStateReportMD5 = configMD5
		return true
	}
	return false
}

func (a *Agent) logMetricsSummary(m Metrics) {
	gpuSummary, _ := json.Marshal(m.GPUInfo)
	a.log.debugf("metrics summary cpu=%s gpu_info=%s", m.CPU, string(gpuSummary))
}

func (a *Agent) postReportBody(cfg Config, body []byte, sampleCount int, fallback bool) (int, error) {
	label := "report"
	if fallback {
		label = "POST fallback"
	}
	a.log.debugf("%s attempt url=%s payload_bytes=%d samples=%d", label, cfg.WorkerURL, len(body), sampleCount)
	req, err := http.NewRequest(http.MethodPost, cfg.WorkerURL, bytes.NewReader(body))
	if err != nil {
		a.log.warnf("create %s request failed: %v", label, err)
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Config-Schema", configSchemaVersion)
	req.Header.Set("X-Agent-Config-Md5", cfg.ConfigMD5)
	a.setAgentHeaders(req)
	req.Header.Set("X-Agent-Config-Schema", configSchemaVersion)
	req.Header.Set("X-Agent-Version", a.version)
	req.Header.Set("X-Agent-Config-Md5", firstNonEmpty(cfg.ConfigMD5, "none"))

	started := time.Now()
	resp, err := sharedReportHTTPClient(time.Duration(cfg.ReportTimeoutMS)*time.Millisecond, usePublicDNSResolver(cfg)).Do(req)
	if err != nil {
		a.log.warnf("%s failed: %v", label, err)
		return 0, err
	}
	headerReceived := time.Now()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	respHeaders := resp.Header
	reportHTTPCode := resp.StatusCode
	a.handleTimedReportResponse(reportHTTPCode, respBody, respHeaders, started, headerReceived)
	return reportHTTPCode, nil
}

func (a *Agent) samplesForReport() []map[string]any {
	samples := make([]map[string]any, 0, len(a.samples))
	for _, sample := range a.samples {
		timestamp, _ := a.clock.timestamp(sample.at)
		samples = append(samples, map[string]any{
			"ts":      timestamp,
			"metrics": sample.metrics,
		})
	}
	return samples
}

func (a *Agent) metricsForReport(m Metrics, reportAt time.Time) map[string]any {
	metrics := metricsToMap(m)
	bootTime, err := strconv.ParseInt(m.BootTime, 10, 64)
	if err == nil && bootTime > 0 {
		metrics["boot_time"] = strconv.FormatInt(a.clock.correctLocalTimestamp(bootTime, reportAt), 10)
	}
	return metrics
}

func (a *Agent) handleReportResponse(statusCode int, respBody []byte, headers http.Header) {
	now := time.Now()
	a.handleTimedReportResponse(statusCode, respBody, headers, now, now)
}

func (a *Agent) handleTimedReportResponse(statusCode int, respBody []byte, headers http.Header, started, received time.Time) {
	a.log.debugf("report response http=%d body=%s", statusCode, strings.TrimSpace(string(respBody)))
	if statusCode < 200 || statusCode >= 300 {
		return
	}
	a.handleWSSRuntimeHeaders(headers)
	if dateTime, ok := responseDateTime(headers); ok {
		snapshot, updated := a.clock.updateDate(dateTime, received.Sub(started), received)
		if updated {
			a.log.debugf("Date header time calibrated offset_ms=%d round_trip_ms=%d",
				valueOrZero(snapshot.OffsetMS), valueOrZero(snapshot.RoundTripMS))
		} else {
			a.log.debugf("Date header time calibration skipped offset_ms=%d threshold_ms=%d",
				valueOrZero(snapshot.OffsetMS), int64(dateCalibrationThreshold/time.Millisecond))
		}
	}
	rawBody := strings.TrimSpace(string(respBody))
	if rawBody == "" || rawBody == "{}" || strings.EqualFold(rawBody, "OK") {
		return
	}
	if strings.HasPrefix(rawBody, "{") {
		var envelope map[string]json.RawMessage
		if json.Unmarshal(respBody, &envelope) == nil && len(envelope) == 0 {
			return
		}
	}
	if statusCode == http.StatusOK {
		if err := a.applyRemoteConfig(respBody, headers); err != nil {
			a.log.warnf("dynamic configuration rejected: %v", err)
		}
	}
}

func valueOrZero[T ~int64 | ~uint64](value *T) T {
	if value == nil {
		return 0
	}
	return *value
}

func (a *Agent) networkWorker(ctx context.Context) {
	var lastIP, lastProbe time.Time
	histories := make(map[string]*rollingProbeHistory)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.networkWake:
			lastProbe = time.Time{}
			resetTimer(timer, 0)
		case now := <-timer.C:
			cfg := a.configSnapshot()
			snap := ProbeSnapshot{Results: make(map[string]ProbeResult, len(cfg.Probes))}
			needUpdate := false
			ipInterval := time.Duration(cfg.IPRefreshInterval) * time.Second
			probeInterval := time.Duration(cfg.ProbeInterval) * time.Second
			probeWindow := time.Duration(cfg.ProbeWindow) * time.Second
			maxSamples := (cfg.ProbeWindow + cfg.ProbeInterval - 1) / cfg.ProbeInterval
			if lastIP.IsZero() || now.Sub(lastIP) >= ipInterval {
				usePublicDNS := usePublicDNSResolver(cfg)
				lookupTimeout := time.Duration(cfg.IPLookupTimeoutMS) * time.Millisecond
				snap.IPv4 = lookupPublicIP("tcp4", cfg.IPv4LookupURLs, lookupTimeout, a.log, usePublicDNS)
				snap.IPv6 = lookupPublicIP("tcp6", cfg.IPv6LookupURLs, lookupTimeout, a.log, usePublicDNS)
				lastIP = now
				needUpdate = true
			}
			if lastProbe.IsZero() || now.Sub(lastProbe) >= probeInterval {
				a.log.debugf("network probe run nodes=%d interval=%ds window=%ds", len(cfg.Probes), cfg.ProbeInterval, cfg.ProbeWindow)
				type measuredProbe struct {
					node   ProbeNode
					result ProbeResult
				}
				results := make(chan measuredProbe, len(cfg.Probes))
				semaphore := make(chan struct{}, cfg.ProbeConcurrency)
				var workers sync.WaitGroup
				for _, node := range cfg.Probes {
					node := node
					workers.Add(1)
					go func() {
						defer workers.Done()
						select {
						case semaphore <- struct{}{}:
						case <-ctx.Done():
							return
						}
						defer func() { <-semaphore }()
						result := measureProbe(node.Mode, node.Target, 1, defaultMetricsTCPPort, time.Duration(cfg.ProbeTimeoutMS)*time.Millisecond, a.log)
						select {
						case results <- measuredProbe{node: node, result: result}:
						case <-ctx.Done():
						}
					}()
				}
				workers.Wait()
				close(results)
				active := make(map[string]struct{}, len(cfg.Probes))
				for measured := range results {
					active[measured.node.ID] = struct{}{}
					history := histories[measured.node.ID]
					if history == nil {
						history = &rollingProbeHistory{}
						histories[measured.node.ID] = history
					}
					history.add(now, probeHistoryKey(measured.node.Mode, measured.node.Target), measured.result, maxSamples)
					snap.Results[measured.node.ID] = history.snapshot(now, probeWindow, maxSamples)
				}
				for id := range histories {
					if _, ok := active[id]; !ok {
						delete(histories, id)
					}
				}
				lastProbe = now
				needUpdate = true
			}
			if needUpdate {
				a.mu.Lock()
				if snap.IPv4 == "" {
					snap.IPv4 = a.probes.IPv4
				}
				if snap.IPv6 == "" {
					snap.IPv6 = a.probes.IPv6
				}
				if len(snap.Results) == 0 && len(cfg.Probes) > 0 {
					snap.Results = a.probes.Results
				}
				snap.Version = a.probes.Version + 1
				a.probes = snap
				a.mu.Unlock()
				a.log.debugf("network probe update ipv4=%s ipv6=%s results=%d configured=%d", snap.IPv4, snap.IPv6, len(snap.Results), len(cfg.Probes))
				// The regular sampler will attach this snapshot to the next point.
				// Keeping probe completion off the report scheduler preserves a
				// stable sampling cadence and avoids extra idle-time reports.
			}
			nextIP := ipInterval
			if !lastIP.IsZero() {
				nextIP = time.Until(lastIP.Add(ipInterval))
			}
			nextProbe := probeInterval
			if !lastProbe.IsZero() {
				nextProbe = time.Until(lastProbe.Add(probeInterval))
			}
			next := min(nextIP, nextProbe)
			if next < 100*time.Millisecond {
				next = 100 * time.Millisecond
			}
			resetTimer(timer, next)
		}
	}
}

var remoteBodyRE = regexp.MustCompile(`^[A-Za-z0-9_=&.,:%+\-\*\?\[\]]*$`)

func (a *Agent) applyRemoteConfig(body []byte, headers http.Header) error {
	return a.applyRemoteConfigWithOptions(body, headers, false)
}

func (a *Agent) applyWSSRemoteConfig(body []byte, headers http.Header) error {
	if a == nil || a.remoteConfig == nil || a.ctx == nil {
		return a.applyRemoteConfigWithOptions(body, headers, true)
	}
	req := remoteConfigRequest{
		body:            append([]byte(nil), body...),
		headers:         headers.Clone(),
		allowMissingMD5: true,
		done:            make(chan error, 1),
	}
	select {
	case a.remoteConfig <- req:
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
	select {
	case err := <-req.done:
		return err
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
}

func (a *Agent) applyRemoteConfigWithOptions(body []byte, headers http.Header, allowMissingMD5 bool) error {
	if len(body) == 0 {
		return errors.New("empty body")
	}
	if len(body) > 64*1024 {
		return errors.New("response too large")
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return errors.New("empty body")
	}
	if !remoteBodyRE.MatchString(raw) {
		return errors.New("invalid body characters")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		"collect_interval":     true,
		"report_interval":      true,
		"wss_report_interval":  true,
		"reset_day":            true,
		"schema_version":       true,
		"probes":               true,
		"probe_interval":       true,
		"probe_window":         true,
		"probe_concurrency":    true,
		"probe_timeout_ms":     true,
		"ip_refresh_interval":  true,
		"report_timeout_ms":    true,
		"dns_cache_seconds":    true,
		"ip_lookup_timeout_ms": true,
		"ipv4_lookup_urls":     true,
		"ipv6_lookup_urls":     true,
		"interface":            true,
		"connection_mode":      true,
		"rx_correction":        true,
		"tx_correction":        true,
		"update":               true,
	}
	for key := range values {
		if !allowed[key] {
			return fmt.Errorf("unknown field %s", key)
		}
	}
	update := values.Get("update")
	if update != "" && update != "0" && update != "1" {
		return fmt.Errorf("invalid update %s", update)
	}
	hasConfig := values.Has("schema_version") || values.Has("probes")
	hasCorrection := values.Has("rx_correction") || values.Has("tx_correction")
	cfg := a.configSnapshot()
	if !hasConfig {
		if hasCorrection {
			rx := values.Get("rx_correction")
			tx := values.Get("tx_correction")
			if err := applyTrafficCorrection(a.paths.TrafficFile, readNetBytes(cfg.Interface), cfg.Interface, rx, tx); err != nil {
				return err
			}
			a.traffic = readTrafficState(a.paths.TrafficFile)
			_ = a.sendCorrectionConfirm(cfg, rx, tx)
			return nil
		}
		if values.Has("update") {
			return nil
		}
		return errors.New("no config fields")
	}
	newMD5 := strings.ToLower(strings.TrimSpace(headers.Get("X-Agent-Config-Md5")))
	hasRemoteMD5 := validConfigMD5(newMD5)
	if !hasRemoteMD5 && !allowMissingMD5 {
		return errors.New("invalid remote md5")
	}
	collect := parseIntDefault(values.Get("collect_interval"), -1)
	report := parseIntDefault(values.Get("report_interval"), -1)
	wssReport := parseIntDefault(values.Get("wss_report_interval"), defaultWSSReportIntervalSec)
	probeInterval := parseIntDefault(values.Get("probe_interval"), -1)
	probeWindow := parseIntDefault(values.Get("probe_window"), -1)
	probeConcurrency := parseIntDefault(values.Get("probe_concurrency"), -1)
	probeTimeoutMS := parseIntDefault(values.Get("probe_timeout_ms"), -1)
	ipRefreshInterval := parseIntDefault(values.Get("ip_refresh_interval"), -1)
	reportTimeoutMS := parseIntDefault(values.Get("report_timeout_ms"), -1)
	dnsCacheSeconds := parseIntDefault(values.Get("dns_cache_seconds"), -1)
	ipLookupTimeoutMS := parseIntDefault(values.Get("ip_lookup_timeout_ms"), -1)
	reset := parseIntDefault(values.Get("reset_day"), -1)
	if !inIntSet(collect, 0, 1, 2, 3, 4, 5, 10) {
		return fmt.Errorf("invalid collect_interval %d", collect)
	}
	if !inIntSet(report, 30, 60, 120, 180) {
		return fmt.Errorf("invalid report_interval %d", report)
	}
	if wssReport < minWSSReportIntervalSec || wssReport > maxWSSReportIntervalSec {
		return fmt.Errorf("invalid wss_report_interval %d", wssReport)
	}
	if probeInterval < 5 || probeInterval > 300 {
		return fmt.Errorf("invalid probe_interval %d", probeInterval)
	}
	if probeWindow < probeInterval || probeWindow > 3600 {
		return fmt.Errorf("invalid probe_window %d", probeWindow)
	}
	if probeConcurrency < 1 || probeConcurrency > 16 {
		return fmt.Errorf("invalid probe_concurrency %d", probeConcurrency)
	}
	if probeTimeoutMS < 250 || probeTimeoutMS > 10000 {
		return fmt.Errorf("invalid probe_timeout_ms %d", probeTimeoutMS)
	}
	if ipRefreshInterval < 60 || ipRefreshInterval > 86400 {
		return fmt.Errorf("invalid ip_refresh_interval %d", ipRefreshInterval)
	}
	if reportTimeoutMS < 1000 || reportTimeoutMS > 60000 {
		return fmt.Errorf("invalid report_timeout_ms %d", reportTimeoutMS)
	}
	if dnsCacheSeconds < 30 || dnsCacheSeconds > 86400 {
		return fmt.Errorf("invalid dns_cache_seconds %d", dnsCacheSeconds)
	}
	if ipLookupTimeoutMS < 1000 || ipLookupTimeoutMS > 60000 {
		return fmt.Errorf("invalid ip_lookup_timeout_ms %d", ipLookupTimeoutMS)
	}
	if reset < 0 || reset > 31 {
		return fmt.Errorf("invalid reset_day %d", reset)
	}
	if values.Get("schema_version") != configSchemaVersion {
		return fmt.Errorf("invalid schema_version %s", values.Get("schema_version"))
	}
	if report < collect {
		return errors.New("report_interval less than collect_interval")
	}
	iface, err := normalizeInterfaceList(values.Get("interface"))
	if err != nil {
		return err
	}
	connectionMode, err := normalizeConnectionMode(values.Get("connection_mode"))
	if err != nil {
		return err
	}
	var probes []ProbeNode
	if err := json.Unmarshal([]byte(values.Get("probes")), &probes); err != nil {
		return fmt.Errorf("invalid probes: %w", err)
	}
	probes, err = normalizeProbeNodes(probes)
	if err != nil {
		return err
	}
	var ipv4LookupURLs, ipv6LookupURLs []string
	if err := json.Unmarshal([]byte(values.Get("ipv4_lookup_urls")), &ipv4LookupURLs); err != nil {
		return fmt.Errorf("invalid ipv4_lookup_urls: %w", err)
	}
	if err := json.Unmarshal([]byte(values.Get("ipv6_lookup_urls")), &ipv6LookupURLs); err != nil {
		return fmt.Errorf("invalid ipv6_lookup_urls: %w", err)
	}
	ipv4LookupURLs, err = normalizeLookupURLs(ipv4LookupURLs)
	if err != nil {
		return err
	}
	ipv6LookupURLs, err = normalizeLookupURLs(ipv6LookupURLs)
	if err != nil {
		return err
	}
	effectiveCollect := collect
	if connectionMode == connectionModeAuto && (collect == 0 || collect > wssReport) {
		effectiveCollect = wssReport
	}
	shouldApply := false
	if hasRemoteMD5 {
		shouldApply = newMD5 != cfg.ConfigMD5
	} else {
		shouldApply = remoteConfigDiffers(cfg, probes, ipv4LookupURLs, ipv6LookupURLs, effectiveCollect, report, probeInterval, probeWindow, probeConcurrency, probeTimeoutMS, ipRefreshInterval, reportTimeoutMS, dnsCacheSeconds, ipLookupTimeoutMS, reset, iface, connectionMode)
	}
	if shouldApply {
		nextCfg := cfg
		nextCfg.CollectInterval = effectiveCollect
		nextCfg.ReportInterval = report
		nextCfg.ProbeInterval = probeInterval
		nextCfg.ProbeWindow = probeWindow
		nextCfg.ProbeConcurrency = probeConcurrency
		nextCfg.ProbeTimeoutMS = probeTimeoutMS
		nextCfg.IPRefreshInterval = ipRefreshInterval
		nextCfg.ReportTimeoutMS = reportTimeoutMS
		nextCfg.DNSCacheSeconds = dnsCacheSeconds
		nextCfg.IPLookupTimeoutMS = ipLookupTimeoutMS
		nextCfg.IPv4LookupURLs = ipv4LookupURLs
		nextCfg.IPv6LookupURLs = ipv6LookupURLs
		nextCfg.ResetDay = reset
		nextCfg.Probes = probes
		nextCfg.Interface = iface
		nextCfg.ConnectionMode = connectionMode
		if hasRemoteMD5 {
			nextCfg.ConfigMD5 = newMD5
		}
		if err := writeConfig(a.paths.ConfigFile, nextCfg); err != nil {
			// Remote configuration must take effect in the running agent even when
			// the installation directory is read-only (for example ProtectSystem).
			// The next report will advertise the old persisted md5 and the control
			// plane can resend the configuration after a restart.
			a.log.warnf("persist dynamic configuration failed; applying it in memory: %v", err)
		}
		a.setConfig(nextCfg)
		now := time.Now()
		a.prevNet = readNetBytes(nextCfg.Interface)
		a.prevTime = now
		a.prevDisk = DiskIOCounters{}
		a.prevDiskAt = time.Time{}
		a.diskIO = DiskIOStats{}
		a.traffic = readTrafficState(a.paths.TrafficFile)
		a.fullAt = time.Time{}
		a.samples = nil
		a.lastSample = time.Time{}
		a.lastReport = time.Time{}
		a.lastPost = time.Time{}
		a.lastPostAttempt = time.Time{}
		a.lastConfigStateReportAt = time.Time{}
		a.lastConfigStateReportMD5 = ""
		if a.reporter != nil {
			a.reporter.resetReportInterval()
		}
		a.syncReportTransport()
		a.wakeTick()
		// A remote probe configuration changes the network worker's schedule.
		// Wake that worker directly so a newly selected node is measured now
		// instead of waiting for the previous IP/probe timer to expire.
		a.wakeNetwork()
		a.log.info("dynamic configuration applied md5=%s connection_mode=%s probes=%d interface=%s", firstNonEmpty(nextCfg.ConfigMD5, "none"), nextCfg.ConnectionMode, len(nextCfg.Probes), firstNonEmpty(iface, "auto"))
		cfg = nextCfg
	}
	if hasCorrection {
		rx := values.Get("rx_correction")
		tx := values.Get("tx_correction")
		if err := applyTrafficCorrection(a.paths.TrafficFile, readNetBytes(cfg.Interface), cfg.Interface, rx, tx); err != nil {
			return err
		}
		a.traffic = readTrafficState(a.paths.TrafficFile)
		_ = a.sendCorrectionConfirm(cfg, rx, tx)
	}
	return nil
}

func (a *Agent) wakeNetwork() {
	if a == nil || a.networkWake == nil {
		return
	}
	select {
	case a.networkWake <- struct{}{}:
	default:
	}
}
func validConfigMD5(value string) bool {
	return len(value) == 32 && !strings.ContainsFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f')
	})
}

func (a *Agent) syncReportTransport() {
	if a.usesWSS() {
		if a.ctx == nil {
			return
		}
		if a.reporter == nil {
			a.reporter = newReportTransport(a)
		}
		a.reporter.start(a.ctx)
		return
	}
	if a.reporter != nil {
		a.reporter.stop("connection_mode=http")
	}
}

func remoteConfigDiffers(cfg Config, probes []ProbeNode, ipv4LookupURLs, ipv6LookupURLs []string, collect, report, probeInterval, probeWindow, probeConcurrency, probeTimeoutMS, ipRefreshInterval, reportTimeoutMS, dnsCacheSeconds, ipLookupTimeoutMS, reset int, iface, connectionMode string) bool {
	return cfg.CollectInterval != collect ||
		cfg.ReportInterval != report ||
		cfg.ProbeInterval != probeInterval ||
		cfg.ProbeWindow != probeWindow ||
		cfg.ProbeConcurrency != probeConcurrency ||
		cfg.ProbeTimeoutMS != probeTimeoutMS ||
		cfg.IPRefreshInterval != ipRefreshInterval ||
		cfg.ReportTimeoutMS != reportTimeoutMS ||
		cfg.DNSCacheSeconds != dnsCacheSeconds ||
		cfg.IPLookupTimeoutMS != ipLookupTimeoutMS ||
		cfg.ResetDay != reset ||
		!probeNodesEqual(cfg.Probes, probes) ||
		!stringSlicesEqual(cfg.IPv4LookupURLs, ipv4LookupURLs) ||
		!stringSlicesEqual(cfg.IPv6LookupURLs, ipv6LookupURLs) ||
		cfg.Interface != iface ||
		cfg.ConnectionMode != connectionMode
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func probeNodesEqual(left, right []ProbeNode) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func inIntSet(v int, allowed ...int) bool {
	for _, item := range allowed {
		if v == item {
			return true
		}
	}
	return false
}

func (a *Agent) setAgentHeaders(req *http.Request) {
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "cfsm")
}

func (a *Agent) sendCorrectionConfirm(cfg Config, rx, tx string) error {
	if _, err := parseTrafficCorrectionGB(rx); err != nil {
		return err
	}
	if _, err := parseTrafficCorrectionGB(tx); err != nil {
		return err
	}
	payload := map[string]any{
		"id":            cfg.ServerID,
		"secret":        cfg.Secret,
		"rx_correction": parseFloatDefault(rx, 0),
		"tx_correction": parseFloatDefault(tx, 0),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, cfg.WorkerURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	a.setAgentHeaders(req)
	client := sharedReportHTTPClient(time.Duration(cfg.ReportTimeoutMS)*time.Millisecond, usePublicDNSResolver(cfg))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	statusCode := resp.StatusCode
	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("http %d", statusCode)
	}
	a.log.info("traffic correction confirm sent rx=%sGB tx=%sGB", firstNonEmpty(rx, "0"), firstNonEmpty(tx, "0"))
	return nil
}
func parseFloatDefault(raw string, def float64) float64 {
	if strings.TrimSpace(raw) == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return v
}
