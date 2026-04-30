package config

type ModulesConfig struct {
	MAM              bool `yaml:"mam"`
	Push             bool `yaml:"push"`
	Carbons          bool `yaml:"carbons"`
	MUC              bool `yaml:"muc"`
	HTTPUpload       bool `yaml:"http_upload"`
	PEP              bool `yaml:"pep"`
	SM               bool `yaml:"sm"`
	CSI              bool `yaml:"csi"`
	SPQRItemMaxBytes int  `yaml:"spqr_item_max_bytes"`
}
