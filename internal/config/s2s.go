package config

type S2SConfig struct {
	Enabled            bool     `yaml:"enabled"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	AllowedDomains     []string `yaml:"allowed_domains"`
	DialbackEnabled    bool     `yaml:"dialback_enabled"`
	MTLSEnabled        bool     `yaml:"mtls_enabled"`
	CertFile           string   `yaml:"cert_file"`
	KeyFile            string   `yaml:"key_file"`
	ClientCAFile       string   `yaml:"client_ca_file"`
}
