package carbons

import (
	"bytes"
	"context"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func (m *Manager) DeliverCarbons(
	ctx context.Context,
	ownerBare stanza.JID,
	originalRecipient stanza.JID,
	original []byte,
	direction int,
	allBoundResources []stanza.JID,
) int {
	if hasCarbonHint(original, "no-copy") || hasCarbonHint(original, "private") {
		return 0
	}

	delivered := 0
	for _, res := range allBoundResources {
		if res.Equal(originalRecipient) {
			continue
		}
		if !m.IsEnabled(res) {
			continue
		}

		var wrapped []byte
		if direction == 0 {
			wrapped = m.WrapReceived(res, originalRecipient, original)
		} else {
			wrapped = m.WrapSent(res, originalRecipient, original)
		}

		if err := m.router.RouteToFull(ctx, res, wrapped); err != nil {
			m.logger.Warn("carbons deliver failed", "to", res.String(), "err", err)
			continue
		}
		delivered++
	}
	return delivered
}

func hasCarbonHint(raw []byte, hint string) bool {
	return bytes.Contains(raw, []byte("<"+hint)) || bytes.Contains(raw, []byte(hint+"/>"))
}
