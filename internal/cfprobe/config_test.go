package cfprobe

import (
	"os"
	"strings"
	"testing"
)

func TestNormalizeInterfaceList(t *testing.T) {
	got, err := normalizeInterfaceList(" eth0,ens3,eth0, pppoe-wan ")
	if err != nil {
		t.Fatalf("normalizeInterfaceList returned error: %v", err)
	}
	if got != "eth0,ens3,pppoe-wan" {
		t.Fatalf("unexpected normalized interfaces: %q", got)
	}
}

func TestNormalizeInterfaceListRejectsBadName(t *testing.T) {
	if _, err := normalizeInterfaceList("eth0, bad/name"); err == nil {
		t.Fatal("expected invalid interface name to be rejected")
	}
}

func TestNormalizeInterfaceListAllowsGlob(t *testing.T) {
	got, err := normalizeInterfaceList(" eth*,en[ops]* ")
	if err != nil {
		t.Fatalf("normalizeInterfaceList returned error: %v", err)
	}
	if got != "eth*,en[ops]*" {
		t.Fatalf("unexpected normalized interfaces: %q", got)
	}
}

func TestConfigPersistsUpdateProxy(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/report"
	cfg.AutoUpdate = true
	cfg.UpdateProxy = "https://gh-proxy.example.com"
	cfg.ConnectionMode = connectionModeHTTP
	cfg.ReportTimeoutMS = 9500
	cfg.DNSCacheSeconds = 900
	cfg.IPLookupTimeoutMS = 4500
	cfg.IPv4LookupURLs = []string{"https://v4.example.com/ip"}
	cfg.IPv6LookupURLs = []string{"https://v6.example.com/ip"}
	cfg.UpdateCheckInterval = 43200
	cfg.StateDir = t.TempDir() + "/state"
	cfg.Probes = []ProbeNode{{ID: "edge", Target: "example.com:443", Mode: pingModeTCP}, {ID: "lan", Target: "192.0.2.1", Mode: pingModeICMP}}

	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.UpdateProxy != cfg.UpdateProxy {
		t.Fatalf("UpdateProxy = %q, want %q", got.UpdateProxy, cfg.UpdateProxy)
	}
	if !got.AutoUpdate {
		t.Fatal("AutoUpdate = false, want true")
	}
	if got.ConnectionMode != connectionModeHTTP {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeHTTP)
	}
	if !probeNodesEqual(got.Probes, cfg.Probes) {
		t.Fatalf("Probes = %#v, want %#v", got.Probes, cfg.Probes)
	}
	if got.ReportTimeoutMS != cfg.ReportTimeoutMS || got.DNSCacheSeconds != cfg.DNSCacheSeconds || got.IPLookupTimeoutMS != cfg.IPLookupTimeoutMS {
		t.Fatalf("runtime timeouts were not persisted: got %+v", got)
	}
	if len(got.IPv4LookupURLs) != 1 || got.IPv4LookupURLs[0] != cfg.IPv4LookupURLs[0] || len(got.IPv6LookupURLs) != 1 || got.IPv6LookupURLs[0] != cfg.IPv6LookupURLs[0] {
		t.Fatalf("lookup URLs were not persisted: v4=%#v v6=%#v", got.IPv4LookupURLs, got.IPv6LookupURLs)
	}
	if got.UpdateCheckInterval != cfg.UpdateCheckInterval {
		t.Fatalf("UpdateCheckInterval = %d, want %d", got.UpdateCheckInterval, cfg.UpdateCheckInterval)
	}
	if got.StateDir != cfg.StateDir {
		t.Fatalf("StateDir = %q, want %q", got.StateDir, cfg.StateDir)
	}
}

func TestReadConfigInvalidatesRemoteMD5WhenManagedConfigChanges(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.ConfigMD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	changed := strings.Replace(string(data), `RESET_DAY="1"`, `RESET_DAY="8"`, 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatalf("change config: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.ConfigMD5 != "none" {
		t.Fatalf("ConfigMD5 = %q, want none after local managed config changed", got.ConfigMD5)
	}
	if got.ResetDay != 8 {
		t.Fatalf("ResetDay = %d, want locally parsed value before remote resync", got.ResetDay)
	}
}

func TestReadConfigInvalidatesRemoteMD5WhenManagedFieldMissing(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	cfg := defaultConfig()
	cfg.ServerID = "sid"
	cfg.Secret = "secret"
	cfg.WorkerURL = "https://worker.example.com/update"
	cfg.ConfigMD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	withoutResetDay := strings.Replace(string(data), `RESET_DAY="1"`+"\n", "", 1)
	if err := os.WriteFile(path, []byte(withoutResetDay), 0o600); err != nil {
		t.Fatalf("change config: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig returned error: %v", err)
	}
	if got.ConfigMD5 != "none" {
		t.Fatalf("ConfigMD5 = %q, want none when RESET_DAY is missing", got.ConfigMD5)
	}
}

func TestReadConfigRejectsObsoleteSchema(t *testing.T) {
	path := t.TempDir() + "/config.conf"
	data := []byte("SERVER_ID=\"sid\"\nSECRET=\"secret\"\nWORKER_URL=\"https://worker.example.com/update\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("expected obsolete config schema to be rejected")
	}
}
