// SPDX-License-Identifier: AGPL-3.0-or-later
package x3dhpq

type RecoveryNodePolicy struct {
	ItemMaxBytes int64
	AccessModel  int
}

func DefaultRecoveryNodePolicy() RecoveryNodePolicy {
	return RecoveryNodePolicy{ItemMaxBytes: 32 << 10, AccessModel: 4}
}
