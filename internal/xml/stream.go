// Package xml provides streaming XMPP XML reading and writing.
package xml

const (
	NSStream = "http://etherx.jabber.org/streams"
	NSClient = "jabber:client"
	NSServer = "jabber:server"
)

type StreamHeader struct {
	From, To, ID, Version, Lang string
}
