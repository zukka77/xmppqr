package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRoundTrip(t *testing.T) {
	orig := Defaults()
	orig.Server.Domain = "example.com"

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := &Config{}
	if err := yaml.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Server.Domain != orig.Server.Domain {
		t.Errorf("domain: got %q want %q", got.Server.Domain, orig.Server.Domain)
	}
	if got.Listeners.C2SStartTLS != orig.Listeners.C2SStartTLS {
		t.Errorf("c2s_starttls: got %q want %q", got.Listeners.C2SStartTLS, orig.Listeners.C2SStartTLS)
	}
	if got.TLS.MinVersion != orig.TLS.MinVersion {
		t.Errorf("tls.min_version: got %q want %q", got.TLS.MinVersion, orig.TLS.MinVersion)
	}
	if got.Modules.SPQRItemMaxBytes != orig.Modules.SPQRItemMaxBytes {
		t.Errorf("spqr_item_max_bytes: got %d want %d", got.Modules.SPQRItemMaxBytes, orig.Modules.SPQRItemMaxBytes)
	}
}

func TestDefaultsApplied(t *testing.T) {
	f, err := os.CreateTemp("", "xmppqr-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("server:\n  domain: test.example\n")
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listeners.C2SStartTLS != ":5222" {
		t.Errorf("default C2SStartTLS: got %q", cfg.Listeners.C2SStartTLS)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default log level: got %q", cfg.Log.Level)
	}
	if !cfg.TLS.PreferPQHybrid {
		t.Error("default PreferPQHybrid should be true")
	}
	if cfg.Modules.SPQRItemMaxBytes != 256*1024 {
		t.Errorf("default SPQRItemMaxBytes: got %d", cfg.Modules.SPQRItemMaxBytes)
	}
}

func TestValidateMissingDomain(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing domain")
	}
}

func TestValidateNoListeners(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Domain = "example.com"
	cfg.Listeners = ListenersConfig{}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for no listeners")
	}
}

func TestValidateOK(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Domain = "example.com"
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
