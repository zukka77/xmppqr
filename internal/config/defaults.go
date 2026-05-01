package config

func Defaults() *Config {
	return &Config{
		Listeners: ListenersConfig{
			C2SStartTLS: ":5222",
			C2SDirectTLS: ":5223",
			S2S:          ":5269",
			HTTPUpload:   ":5443",
			AdminPProf:   "127.0.0.1:6060",
		},
		TLS: TLSConfig{
			MinVersion:     "TLS1.2",
			PreferPQHybrid: true,
		},
		DB: DBConfig{
			Driver: "memory",
		},
		Log: LogConfig{
			Level:         "info",
			Format:        "text",
			RedactStanzas: true,
		},
		Modules: ModulesConfig{
			MAM:              true,
			Push:             true,
			Carbons:          true,
			MUC:              true,
			HTTPUpload:       true,
			PEP:              true,
			SM:               true,
			CSI:              true,
			SPQRItemMaxBytes: 256 * 1024,
		},
		S2S: S2SConfig{
			Enabled:         false,
			DialbackEnabled: true,
			MTLSEnabled:     false,
		},
	}
}
