package cfprobe

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	ifacePartRE = regexp.MustCompile(`^[A-Za-z0-9_.:\-\*\?\[\]]+$`)
	probeIDRE   = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

var defaultIPv4LookupURLs = []string{
	"https://www.visa.cn/cdn-cgi/trace",
	"https://www.qualcomm.cn/cdn-cgi/trace",
	"https://edge-ip.html.zone/geo",
	"https://vercel-ip.html.zone/geo",
	"https://ipv4.ip.sb",
	"https://api.ipify.org?format=json",
	"https://cloudflare.com/cdn-cgi/trace",
}

var defaultIPv6LookupURLs = []string{
	"https://v6.ip.zxinc.org/info.php?type=json",
	"https://api6.ipify.org?format=json",
	"https://ipv6.icanhazip.com",
	"https://api-ipv6.ip.sb/geoip",
	"https://cloudflare.com/cdn-cgi/trace",
}

func defaultConfig() Config {
	return Config{
		CollectInterval:     0,
		ReportInterval:      defaultReportIntervalSec,
		ProbeInterval:       20,
		ProbeWindow:         120,
		ProbeConcurrency:    4,
		ProbeTimeoutMS:      1500,
		IPRefreshInterval:   600,
		ReportTimeoutMS:     8000,
		DNSCacheSeconds:     1800,
		IPLookupTimeoutMS:   8000,
		IPv4LookupURLs:      append([]string(nil), defaultIPv4LookupURLs...),
		IPv6LookupURLs:      append([]string(nil), defaultIPv6LookupURLs...),
		ResetDay:            1,
		ConnectionMode:      connectionModeAuto,
		UpdateCheckInterval: 21600,
		Probes:              []ProbeNode{},
		ConfigMD5:           "none",
	}
}

func normalizeLookupURLs(values []string) ([]string, error) {
	if len(values) > 8 {
		return nil, errors.New("公网 IP 查询接口最多 8 个")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" || len(raw) > 512 {
			return nil, errors.New("公网 IP 查询接口地址非法")
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("公网 IP 查询接口必须是无凭据的 HTTPS 地址: %s", raw)
		}
		normalized := parsed.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func normalizeHTTPURL(raw string, optional bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" && optional {
		return "", nil
	}
	if raw == "" || len(raw) > 2048 {
		return "", errors.New("URL 为空或过长")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("URL 必须使用 http 或 https: %s", raw)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("URL 不允许包含凭据或片段")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateConfigIdentity(cfg Config) error {
	if cfg.ServerID == "" || len(cfg.ServerID) > 128 || strings.ContainsAny(cfg.ServerID, "\r\n\x00") {
		return errors.New("SERVER_ID 非法")
	}
	if cfg.Secret == "" || len(cfg.Secret) > 4096 || strings.ContainsAny(cfg.Secret, "\r\n\x00") {
		return errors.New("SECRET 非法")
	}
	return nil
}

func decodeLookupURLs(raw string, fallback []string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return append([]string(nil), fallback...), nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	var values []string
	if err := json.Unmarshal(decoded, &values); err != nil {
		return nil, err
	}
	return normalizeLookupURLs(values)
}

func normalizeBinaryValue(raw string, def bool) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	switch raw {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("仅支持 0 或 1")
	}
}

func normalizeConnectionMode(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", connectionModeAuto:
		return connectionModeAuto, nil
	case connectionModeHTTP:
		return connectionModeHTTP, nil
	default:
		return "", fmt.Errorf("connection_mode 仅支持 auto 或 http")
	}
}

func normalizeProbeMode(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", pingModeTCP:
		return pingModeTCP, nil
	case pingModeICMP, pingModeHybrid:
		return raw, nil
	default:
		return "", fmt.Errorf("检测方式仅支持 tcp、icmp 或 hybrid")
	}
}

func normalizeProbeNodes(nodes []ProbeNode) ([]ProbeNode, error) {
	if len(nodes) > 64 {
		return nil, errors.New("检测节点最多 64 个")
	}
	seen := make(map[string]struct{}, len(nodes))
	result := make([]ProbeNode, 0, len(nodes))
	for _, node := range nodes {
		node.ID = strings.TrimSpace(node.ID)
		node.Target = strings.TrimSpace(node.Target)
		if node.ID == "" || len(node.ID) > 64 || node.Target == "" || len(node.Target) > 255 {
			return nil, errors.New("检测节点配置非法")
		}
		if !probeIDRE.MatchString(node.ID) {
			return nil, fmt.Errorf("检测节点 ID 非法: %s", node.ID)
		}
		if _, ok := seen[node.ID]; ok {
			return nil, fmt.Errorf("检测节点 ID 重复: %s", node.ID)
		}
		mode, err := normalizeProbeMode(node.Mode)
		if err != nil {
			return nil, err
		}
		node.Mode = mode
		if _, _, err := splitProbeTarget(node.Target, defaultMetricsTCPPort); err != nil {
			return nil, fmt.Errorf("检测节点 %s 地址非法: %w", node.ID, err)
		}
		seen[node.ID] = struct{}{}
		result = append(result, node)
	}
	return result, nil
}

func normalizeInterfaceList(raw string) (string, error) {
	parts := strings.Split(raw, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if len(name) > 64 || !ifacePartRE.MatchString(name) {
			return "", fmt.Errorf("interface 参数非法: %q", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	joined := strings.Join(out, ",")
	if len(joined) > 255 {
		return "", errors.New("interface 参数过长")
	}
	return joined, nil
}

func parseKVFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		values[k] = v
	}
	return values, scanner.Err()
}

func readConfig(path string) (Config, error) {
	cfg := defaultConfig()
	values, err := parseKVFile(path)
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(values["CONFIG_SCHEMA"]) != configSchemaVersion {
		return cfg, fmt.Errorf("CONFIG_SCHEMA 必须为 %s", configSchemaVersion)
	}

	cfg.ServerID = values["SERVER_ID"]
	cfg.Secret = values["SECRET"]
	cfg.WorkerURL = values["WORKER_URL"]
	cfg.CollectInterval = parseIntDefault(values["COLLECT_INTERVAL"], cfg.CollectInterval)
	cfg.ReportInterval = parseIntDefault(values["REPORT_INTERVAL"], cfg.ReportInterval)
	cfg.ProbeInterval = parseIntDefault(values["PROBE_INTERVAL"], cfg.ProbeInterval)
	cfg.ProbeWindow = parseIntDefault(values["PROBE_WINDOW"], cfg.ProbeWindow)
	cfg.ProbeConcurrency = parseIntDefault(values["PROBE_CONCURRENCY"], cfg.ProbeConcurrency)
	cfg.ProbeTimeoutMS = parseIntDefault(values["PROBE_TIMEOUT_MS"], cfg.ProbeTimeoutMS)
	cfg.IPRefreshInterval = parseIntDefault(values["IP_REFRESH_INTERVAL"], cfg.IPRefreshInterval)
	cfg.ReportTimeoutMS = parseIntDefault(values["REPORT_TIMEOUT_MS"], cfg.ReportTimeoutMS)
	cfg.DNSCacheSeconds = parseIntDefault(values["DNS_CACHE_SECONDS"], cfg.DNSCacheSeconds)
	cfg.IPLookupTimeoutMS = parseIntDefault(values["IP_LOOKUP_TIMEOUT_MS"], cfg.IPLookupTimeoutMS)
	cfg.IPv4LookupURLs, err = decodeLookupURLs(values["IPV4_LOOKUP_URLS"], defaultIPv4LookupURLs)
	if err != nil {
		return cfg, fmt.Errorf("IPV4_LOOKUP_URLS 非法: %w", err)
	}
	cfg.IPv6LookupURLs, err = decodeLookupURLs(values["IPV6_LOOKUP_URLS"], defaultIPv6LookupURLs)
	if err != nil {
		return cfg, fmt.Errorf("IPV6_LOOKUP_URLS 非法: %w", err)
	}
	if raw := strings.TrimSpace(values["PROBES"]); raw != "" {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(raw)
		if decodeErr != nil {
			return cfg, fmt.Errorf("PROBES 非法: %w", decodeErr)
		}
		if err := json.Unmarshal(decoded, &cfg.Probes); err != nil {
			return cfg, fmt.Errorf("PROBES 非法: %w", err)
		}
		cfg.Probes, err = normalizeProbeNodes(cfg.Probes)
		if err != nil {
			return cfg, err
		}
	}
	cfg.Interface, _ = normalizeInterfaceList(values["INTERFACE"])
	cfg.ResetDay = parseIntDefault(values["RESET_DAY"], cfg.ResetDay)
	cfg.ConnectionMode, _ = normalizeConnectionMode(values["CONNECTION_MODE"])
	cfg.AutoUpdate = values["AUTO_UPDATE"] == "1"
	cfg.UpdateCheckInterval = parseIntDefault(values["UPDATE_CHECK_INTERVAL"], cfg.UpdateCheckInterval)
	cfg.UpdateProxy = strings.TrimSpace(values["UPDATE_PROXY"])
	cfg.StateDir = strings.TrimSpace(values["STATE_DIR"])
	cfg.ConfigMD5 = values["CONFIG_MD5"]
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	cfg.ConfigFingerprint = strings.ToLower(strings.TrimSpace(values["CONFIG_FINGERPRINT"]))
	normalizeConfigIntervals(&cfg)
	if err := validateConfigIdentity(cfg); err != nil {
		return cfg, err
	}
	cfg.WorkerURL, err = normalizeHTTPURL(cfg.WorkerURL, false)
	if err != nil {
		return cfg, fmt.Errorf("WORKER_URL 非法: %w", err)
	}
	cfg.UpdateProxy, err = normalizeHTTPURL(cfg.UpdateProxy, true)
	if err != nil {
		return cfg, fmt.Errorf("UPDATE_PROXY 非法: %w", err)
	}
	if cfg.ConfigMD5 != "none" && (!hasCompleteManagedConfig(values) || cfg.ConfigFingerprint != managedConfigFingerprint(cfg)) {
		cfg.ConfigMD5 = "none"
	}
	return cfg, nil
}

func writeConfig(path string, cfg Config) error {
	if err := validateConfigIdentity(cfg); err != nil {
		return err
	}
	var err error
	cfg.WorkerURL, err = normalizeHTTPURL(cfg.WorkerURL, false)
	if err != nil {
		return fmt.Errorf("WORKER_URL 非法: %w", err)
	}
	cfg.UpdateProxy, err = normalizeHTTPURL(cfg.UpdateProxy, true)
	if err != nil {
		return fmt.Errorf("UPDATE_PROXY 非法: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	normalizeConfigIntervals(&cfg)
	var buf bytes.Buffer
	writeKV := func(k, v string) {
		fmt.Fprintf(&buf, "%s=\"%s\"\n", k, strings.ReplaceAll(v, `"`, `\"`))
	}
	writeKV("CONFIG_SCHEMA", configSchemaVersion)
	writeKV("SERVER_ID", cfg.ServerID)
	writeKV("SECRET", cfg.Secret)
	writeKV("WORKER_URL", cfg.WorkerURL)
	writeKV("COLLECT_INTERVAL", strconv.Itoa(cfg.CollectInterval))
	writeKV("REPORT_INTERVAL", strconv.Itoa(cfg.ReportInterval))
	writeKV("PROBE_INTERVAL", strconv.Itoa(cfg.ProbeInterval))
	writeKV("PROBE_WINDOW", strconv.Itoa(cfg.ProbeWindow))
	writeKV("PROBE_CONCURRENCY", strconv.Itoa(cfg.ProbeConcurrency))
	writeKV("PROBE_TIMEOUT_MS", strconv.Itoa(cfg.ProbeTimeoutMS))
	writeKV("IP_REFRESH_INTERVAL", strconv.Itoa(cfg.IPRefreshInterval))
	writeKV("REPORT_TIMEOUT_MS", strconv.Itoa(cfg.ReportTimeoutMS))
	writeKV("DNS_CACHE_SECONDS", strconv.Itoa(cfg.DNSCacheSeconds))
	writeKV("IP_LOOKUP_TIMEOUT_MS", strconv.Itoa(cfg.IPLookupTimeoutMS))
	writeLookupURLs := func(key string, values []string) error {
		encoded, err := json.Marshal(values)
		if err != nil {
			return fmt.Errorf("序列化 %s 失败: %w", key, err)
		}
		writeKV(key, base64.RawURLEncoding.EncodeToString(encoded))
		return nil
	}
	if err := writeLookupURLs("IPV4_LOOKUP_URLS", cfg.IPv4LookupURLs); err != nil {
		return err
	}
	if err := writeLookupURLs("IPV6_LOOKUP_URLS", cfg.IPv6LookupURLs); err != nil {
		return err
	}
	probesJSON, err := json.Marshal(cfg.Probes)
	if err != nil {
		return fmt.Errorf("序列化检测节点失败: %w", err)
	}
	writeKV("PROBES", base64.RawURLEncoding.EncodeToString(probesJSON))
	writeKV("INTERFACE", cfg.Interface)
	writeKV("RESET_DAY", strconv.Itoa(cfg.ResetDay))
	writeKV("CONNECTION_MODE", cfg.ConnectionMode)
	if cfg.AutoUpdate {
		writeKV("AUTO_UPDATE", "1")
	} else {
		writeKV("AUTO_UPDATE", "0")
	}
	writeKV("UPDATE_CHECK_INTERVAL", strconv.Itoa(cfg.UpdateCheckInterval))
	writeKV("UPDATE_PROXY", cfg.UpdateProxy)
	writeKV("STATE_DIR", cfg.StateDir)
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	writeKV("CONFIG_MD5", cfg.ConfigMD5)
	cfg.ConfigFingerprint = managedConfigFingerprint(cfg)
	writeKV("CONFIG_FINGERPRINT", cfg.ConfigFingerprint)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var managedConfigKeys = [...]string{
	"COLLECT_INTERVAL",
	"REPORT_INTERVAL",
	"PROBE_INTERVAL",
	"PROBE_WINDOW",
	"PROBE_CONCURRENCY",
	"PROBE_TIMEOUT_MS",
	"IP_REFRESH_INTERVAL",
	"REPORT_TIMEOUT_MS",
	"DNS_CACHE_SECONDS",
	"IP_LOOKUP_TIMEOUT_MS",
	"IPV4_LOOKUP_URLS",
	"IPV6_LOOKUP_URLS",
	"PROBES",
	"INTERFACE",
	"RESET_DAY",
	"CONNECTION_MODE",
}

func hasCompleteManagedConfig(values map[string]string) bool {
	for _, key := range managedConfigKeys {
		if _, ok := values[key]; !ok {
			return false
		}
	}
	return true
}

func managedConfigFingerprint(cfg Config) string {
	managed := struct {
		CollectInterval   int
		ReportInterval    int
		ProbeInterval     int
		ProbeWindow       int
		ProbeConcurrency  int
		ProbeTimeoutMS    int
		IPRefreshInterval int
		ReportTimeoutMS   int
		DNSCacheSeconds   int
		IPLookupTimeoutMS int
		IPv4LookupURLs    []string
		IPv6LookupURLs    []string
		Probes            []ProbeNode
		Interface         string
		ResetDay          int
		ConnectionMode    string
	}{
		CollectInterval:   cfg.CollectInterval,
		ReportInterval:    cfg.ReportInterval,
		ProbeInterval:     cfg.ProbeInterval,
		ProbeWindow:       cfg.ProbeWindow,
		ProbeConcurrency:  cfg.ProbeConcurrency,
		ProbeTimeoutMS:    cfg.ProbeTimeoutMS,
		IPRefreshInterval: cfg.IPRefreshInterval,
		ReportTimeoutMS:   cfg.ReportTimeoutMS,
		DNSCacheSeconds:   cfg.DNSCacheSeconds,
		IPLookupTimeoutMS: cfg.IPLookupTimeoutMS,
		IPv4LookupURLs:    cfg.IPv4LookupURLs,
		IPv6LookupURLs:    cfg.IPv6LookupURLs,
		Probes:            cfg.Probes,
		Interface:         cfg.Interface,
		ResetDay:          cfg.ResetDay,
		ConnectionMode:    cfg.ConnectionMode,
	}
	encoded, _ := json.Marshal(managed)
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum)
}

func normalizeConfigIntervals(cfg *Config) {
	if cfg.CollectInterval < 0 {
		cfg.CollectInterval = 0
	}
	if cfg.ReportInterval < 1 {
		cfg.ReportInterval = defaultReportIntervalSec
	}
	if cfg.CollectInterval > 0 && cfg.ReportInterval < cfg.CollectInterval {
		cfg.ReportInterval = cfg.CollectInterval
	}
	if cfg.ProbeInterval < 5 || cfg.ProbeInterval > 300 {
		cfg.ProbeInterval = 20
	}
	if cfg.ProbeWindow < cfg.ProbeInterval || cfg.ProbeWindow > 3600 {
		cfg.ProbeWindow = max(120, cfg.ProbeInterval)
	}
	if cfg.ProbeConcurrency < 1 || cfg.ProbeConcurrency > 16 {
		cfg.ProbeConcurrency = 4
	}
	if cfg.ProbeTimeoutMS < 250 || cfg.ProbeTimeoutMS > 10000 {
		cfg.ProbeTimeoutMS = 1500
	}
	if cfg.IPRefreshInterval < 60 || cfg.IPRefreshInterval > 86400 {
		cfg.IPRefreshInterval = 600
	}
	if cfg.ReportTimeoutMS < 1000 || cfg.ReportTimeoutMS > 60000 {
		cfg.ReportTimeoutMS = 8000
	}
	if cfg.DNSCacheSeconds < 30 || cfg.DNSCacheSeconds > 86400 {
		cfg.DNSCacheSeconds = 1800
	}
	if cfg.IPLookupTimeoutMS < 1000 || cfg.IPLookupTimeoutMS > 60000 {
		cfg.IPLookupTimeoutMS = 8000
	}
	if urls, err := normalizeLookupURLs(cfg.IPv4LookupURLs); err == nil {
		cfg.IPv4LookupURLs = urls
	} else {
		cfg.IPv4LookupURLs = append([]string(nil), defaultIPv4LookupURLs...)
	}
	if urls, err := normalizeLookupURLs(cfg.IPv6LookupURLs); err == nil {
		cfg.IPv6LookupURLs = urls
	} else {
		cfg.IPv6LookupURLs = append([]string(nil), defaultIPv6LookupURLs...)
	}
	if cfg.ResetDay < 0 || cfg.ResetDay > 31 {
		cfg.ResetDay = 1
	}
	if cfg.UpdateCheckInterval < 300 || cfg.UpdateCheckInterval > 604800 {
		cfg.UpdateCheckInterval = 21600
	}
	if cfg.ConfigMD5 == "" {
		cfg.ConfigMD5 = "none"
	}
	if mode, err := normalizeConnectionMode(cfg.ConnectionMode); err == nil {
		cfg.ConnectionMode = mode
	} else {
		cfg.ConnectionMode = connectionModeAuto
	}
	if probes, err := normalizeProbeNodes(cfg.Probes); err == nil {
		cfg.Probes = probes
	} else {
		cfg.Probes = []ProbeNode{}
	}
	cfg.UpdateProxy = strings.TrimSpace(cfg.UpdateProxy)
}

func parseIntDefault(raw string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return n
}

func parseTrafficCorrectionGB(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || f > maxTrafficCorrectionGB {
		return 0, fmt.Errorf("流量校正值非法: %s", raw)
	}
	return uint64(f * 1024 * 1024 * 1024), nil
}

func splitInterfaceSet(raw string) map[string]bool {
	out := map[string]bool{}
	if raw == "" {
		return out
	}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out[part] = true
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
