package config

type DBConfig struct {
	Driver         string `yaml:"driver"`
	DSN            string `yaml:"dsn"`
	MaxConns       int    `yaml:"max_conns"`
	MigrateOnStart bool   `yaml:"migrate_on_start"`
}
