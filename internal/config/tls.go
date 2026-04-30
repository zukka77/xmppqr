package config

type TLSConfig struct {
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	MinVersion     string `yaml:"min_version"`
	PreferPQHybrid bool   `yaml:"prefer_pq_hybrid"`
	ClientCAFile   string `yaml:"client_ca_file"`
}
