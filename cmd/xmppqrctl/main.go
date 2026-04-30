// Package main implements the xmppqrctl admin CLI for the xmppqr XMPP server.
package main

import (
	"fmt"
	"os"
)

var version = "0.0.0-dev"

func usage() {
	fmt.Fprintf(os.Stderr, `xmppqrctl %s — xmppqr server admin CLI

Subcommands:
  useradd <username>  Add a user (postgres only)
  userlist            List users
  userdel <username>  Delete a user
  migrate             Run database migrations (postgres only)
  tls-probe <host>    Probe TLS handshake details
  version             Print version

Run 'xmppqrctl <subcommand> -h' for subcommand flags.
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	var code int
	switch sub {
	case "useradd":
		code = cmdUseradd(args)
	case "userlist":
		code = cmdUserlist(args)
	case "userdel":
		code = cmdUserdel(args)
	case "migrate":
		code = cmdMigrate(args)
	case "tls-probe":
		code = cmdTLSProbe(args)
	case "version":
		fmt.Printf("xmppqrctl %s (xmppqr server)\n", version)
		code = 0
	case "-h", "--help", "help":
		usage()
		code = 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage()
		code = 2
	}
	os.Exit(code)
}
