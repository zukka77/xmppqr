package config

type ListenersConfig struct {
	C2SStartTLS  string `yaml:"c2s_starttls"`
	C2SDirectTLS string `yaml:"c2s_directtls"`
	S2S          string `yaml:"s2s"`
	HTTPUpload   string `yaml:"http_upload"`
	AdminPProf   string `yaml:"admin_pprof"`
	WebSocket    string `yaml:"websocket"`
}
