package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/danielinux/xmppqr/internal/accountjid"
	"github.com/danielinux/xmppqr/internal/auth"
	"github.com/danielinux/xmppqr/internal/config"
	"github.com/danielinux/xmppqr/internal/storage"
	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func cmdUseradd(args []string) int {
	args = normalizeSinglePositionalArgs(args)
	fs := flag.NewFlagSet("useradd", flag.ContinueOnError)
	domain := fs.String("domain", "", "XMPP domain")
	cfgPath := fs.String("config", "", "config file path")
	password := fs.String("password", "", "password (reads from stdin if omitted)")
	replace := fs.Bool("replace", false, "overwrite existing user")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: useradd <username> [-domain DOMAIN] [-config PATH] [-password PASSWORD] [-replace]")
		return 2
	}
	username := fs.Arg(0)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if *domain == "" {
		*domain = cfg.Server.Domain
	}
	accountJID, _, err := accountjid.Normalize(username, *domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "username:", err)
		return 1
	}

	var passwd []byte
	if *password != "" {
		passwd = []byte(*password)
	} else {
		passwd, err = readPassword("Password: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "read password:", err)
			return 1
		}
	}

	ctx := context.Background()
	stores, closeDB, err := openStores(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage:", err)
		return 1
	}
	defer closeDB()

	if !*replace {
		existing, _ := stores.Users.Get(ctx, accountJID)
		if existing != nil {
			fmt.Fprintf(os.Stderr, "user %q already exists (use -replace to overwrite)\n", accountJID)
			return 1
		}
	}

	salt := make([]byte, 16)
	if _, err := wolfcrypt.Read(salt); err != nil {
		fmt.Fprintln(os.Stderr, "rng:", err)
		return 1
	}
	const iter = 4096

	creds256, err := auth.DeriveSCRAMCreds(passwd, salt, iter, auth.SCRAMSHA256)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scram256:", err)
		return 1
	}
	creds512, err := auth.DeriveSCRAMCreds(passwd, salt, iter, auth.SCRAMSHA512)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scram512:", err)
		return 1
	}
	argon2Hash, err := auth.HashPasswordForStorage(passwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		return 1
	}

	u := &storage.User{
		Username:     accountJID,
		ScramSalt:    salt,
		ScramIter:    iter,
		Argon2Params: argon2Hash,
		StoredKey256: creds256.StoredKey,
		ServerKey256: creds256.ServerKey,
		StoredKey512: creds512.StoredKey,
		ServerKey512: creds512.ServerKey,
		CreatedAt:    time.Now(),
	}
	if err := stores.Users.Put(ctx, u); err != nil {
		fmt.Fprintln(os.Stderr, "put user:", err)
		return 1
	}
	fmt.Printf("user '%s' created\n", accountJID)
	return 0
}

func cmdUserlist(args []string) int {
	fs := flag.NewFlagSet("userlist", flag.ContinueOnError)
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
	stores, closeDB, err := openStores(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage:", err)
		return 1
	}
	defer closeDB()

	users, err := stores.Users.List(ctx, 0, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list:", err)
		return 1
	}
	fmt.Printf("%-32s  %-25s  %s\n", "username", "created_at", "disabled")
	for _, u := range users {
		fmt.Printf("%-32s  %-25s  %v\n", u.Username, u.CreatedAt.Format(time.RFC3339), u.Disabled)
	}
	return 0
}

func cmdUserdel(args []string) int {
	args = normalizeSinglePositionalArgs(args)
	fs := flag.NewFlagSet("userdel", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: userdel <username> [-config PATH]")
		return 2
	}
	username := fs.Arg(0)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	accountJID, _, err := accountjid.Normalize(username, cfg.Server.Domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "username:", err)
		return 1
	}

	ctx := context.Background()
	stores, closeDB, err := openStores(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "storage:", err)
		return 1
	}
	defer closeDB()

	if err := stores.Users.Delete(ctx, accountJID); err != nil {
		fmt.Fprintln(os.Stderr, "delete:", err)
		return 1
	}
	fmt.Printf("user '%s' deleted\n", accountJID)
	return 0
}

func readPassword(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return pw, err
	}
	var pw []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 && buf[0] != '\n' && buf[0] != '\r' {
			pw = append(pw, buf[0])
		}
		if err != nil || (n > 0 && buf[0] == '\n') {
			break
		}
	}
	return pw, nil
}

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}

	if envPath := os.Getenv("XMPPQR_CONFIG"); envPath != "" {
		return config.Load(envPath)
	}

	for _, candidate := range []string{
		"./xmppqrd.yaml",
		"/etc/xmppqr/xmppqrd.yaml",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return config.Load(candidate)
		}
	}

	return config.Defaults(), nil
}

func normalizeSinglePositionalArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	if strings.HasPrefix(args[0], "-") {
		return args
	}
	return append(args[1:], args[0])
}
