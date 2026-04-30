package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func cmdMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}

	ctx := context.Background()
	_, closeDB, db, err := openStoresWithMigrate(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage:", err)
		return 1
	}
	defer closeDB()

	if err := db.Migrate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}
	fmt.Println("migrations applied (or all up to date)")
	return 0
}
