package c2s

import "fmt"

const nsStreams = "urn:ietf:params:xml:ns:xmpp-streams"

func streamError(condition string) []byte {
	return []byte(fmt.Sprintf(
		`<stream:error><%s xmlns='%s'/></stream:error></stream:stream>`,
		condition, nsStreams,
	))
}
