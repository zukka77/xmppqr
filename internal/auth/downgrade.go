package auth

import (
	"sort"
	"strings"

	"github.com/danielinux/xmppqr/internal/wolfcrypt"
)

func ComputeMechanismListHash(mechs []string) []byte {
	sorted := make([]string, len(mechs))
	copy(sorted, mechs)
	sort.Strings(sorted)
	joined := strings.Join(sorted, ",")
	h := wolfcrypt.SHA256([]byte(joined))
	return h[:]
}
