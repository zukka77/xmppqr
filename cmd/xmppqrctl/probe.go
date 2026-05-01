package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	internaltls "github.com/danielinux/xmppqr/internal/tls"
)

func versionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cipherName(id uint16) string {
	switch id {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

func groupName(id uint16) string {
	switch id {
	case internaltls.GroupX25519:
		return "X25519"
	case internaltls.GroupSecp256r1:
		return "P-256"
	case internaltls.GroupSecp384r1:
		return "P-384"
	case internaltls.GroupX25519MLKEM768:
		return "X25519MLKEM768"
	default:
		return fmt.Sprintf("0x%04x", id)
	}
}

func cmdTLSProbe(args []string) int {
	args = normalizeSinglePositionalArgs(args)
	fs := flag.NewFlagSet("tls-probe", flag.ContinueOnError)
	pq := fs.Bool("pq", true, "prefer PQ hybrid key exchange")
	tls12 := fs.Bool("tls12", false, "set min version to TLS 1.2")
	insecure := fs.Bool("insecure", false, "skip certificate verification")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: tls-probe <host:port> [-pq] [-tls12] [-insecure]")
		return 2
	}
	addr := fs.Arg(0)

	opts := internaltls.ClientOptions{
		PreferPQHybrid:     *pq,
		InsecureSkipVerify: *insecure,
	}
	if *tls12 {
		opts.MinVersion = 0x0303
	}

	ctx, err := internaltls.NewClientContext(nil, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls context:", err)
		return 1
	}
	defer ctx.Close()

	conn, err := internaltls.Dial("tcp", addr, ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		return 1
	}
	defer conn.Close()

	hs := conn.HandshakeState()
	fmt.Printf("protocol: %s\n", versionName(hs.Version))
	fmt.Printf("cipher: %s (0x%04x)\n", cipherName(hs.CipherSuite), hs.CipherSuite)
	fmt.Printf("group: %s (0x%04x)\n", groupName(hs.NamedGroup), hs.NamedGroup)
	fmt.Printf("pq-hybrid: %v\n", hs.PQHybrid)
	fmt.Printf("peer-certs: %d\n", len(hs.PeerCertChain))
	fmt.Printf("sni: %s\n", hs.SNI)

	exported, err := conn.Exporter("xmppqrctl-probe", nil, 32)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exporter:", err)
		return 1
	}
	fmt.Printf("exporter: %s\n", hex.EncodeToString(exported))
	return 0
}
