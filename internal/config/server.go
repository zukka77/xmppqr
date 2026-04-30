package config

type ServerConfig struct {
	Domain         string `yaml:"domain"`
	Hostname       string `yaml:"hostname"`
	ResourcePrefix string `yaml:"resource_prefix"`
}
