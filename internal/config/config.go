// Package config loads and validates XMPP server configuration from YAML.
package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Listeners ListenersConfig `yaml:"listeners"`
	TLS       TLSConfig       `yaml:"tls"`
	DB        DBConfig        `yaml:"db"`
	Log       LogConfig       `yaml:"log"`
	Modules   ModulesConfig   `yaml:"modules"`
}

func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Unmarshal into a temp struct so zero-value booleans in YAML don't
	// accidentally override defaults that are true.
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Server.Domain == "" {
		return errors.New("server.domain is required")
	}

	hasListener := c.Listeners.C2SStartTLS != "" ||
		c.Listeners.C2SDirectTLS != "" ||
		c.Listeners.S2S != ""
	if !hasListener {
		return errors.New("at least one of c2s_starttls, c2s_directtls, or s2s listener must be configured")
	}

	if c.TLS.CertFile != "" || c.TLS.KeyFile != "" {
		if c.TLS.CertFile == "" {
			return errors.New("tls.cert_file is required when tls.key_file is set")
		}
		if c.TLS.KeyFile == "" {
			return errors.New("tls.key_file is required when tls.cert_file is set")
		}
		if _, err := os.Stat(c.TLS.CertFile); err != nil {
			return fmt.Errorf("tls.cert_file: %w", err)
		}
		if _, err := os.Stat(c.TLS.KeyFile); err != nil {
			return fmt.Errorf("tls.key_file: %w", err)
		}
	}

	return nil
}
