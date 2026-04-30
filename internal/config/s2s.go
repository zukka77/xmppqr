package config

type S2SConfig struct {
	Enabled            bool     `yaml:"enabled"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	AllowedDomains     []string `yaml:"allowed_domains"`
	DialbackEnabled    bool     `yaml:"dialback_enabled"`
}
