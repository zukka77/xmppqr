package x3dhpq

// AuditChainPolicy carries the per-domain rules for the audit-chain PEP node.
// The server treats the audit chain as opaque (clients verify the hash chain
// + signatures), but this struct exists as a hook for future server-side
// rate-limiting and append-only enforcement.
type AuditChainPolicy struct {
	ItemMaxBytes  int64
	AppendsPerDay int
}

func DefaultAuditChainPolicy() AuditChainPolicy {
	return AuditChainPolicy{ItemMaxBytes: 16 << 10, AppendsPerDay: 50}
}
