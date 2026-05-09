package x3dhpq

const (
	NSRoot       = "urn:xmppqr:x3dhpq:0"
	NSBundle     = "urn:xmppqr:x3dhpq:bundle:0"
	NSDeviceList = "urn:xmppqr:x3dhpq:devicelist:0"
	NSEnvelope   = "urn:xmppqr:x3dhpq:envelope:0"

	NSPair     = "urn:xmppqr:x3dhpq:pair:0"
	NSAudit    = "urn:xmppqr:x3dhpq:audit:0"
	NSRecovery = "urn:xmppqr:x3dhpq:recovery:0"
	NSGroup    = "urn:xmppqr:x3dhpq:group:0"
)

const (
	ElemPair         = "pair"
	ElemVerifyDevice = "verify-device"
	ElemPeers        = "peers"
)

func PlusNotify(ns string) string { return ns + "+notify" }
