package tls

const (
	GroupX25519         = 0x001D
	GroupSecp256r1      = 0x0017
	GroupSecp384r1      = 0x0018
	GroupX25519MLKEM768 = 0x11EC
)

func defaultGroupPreference(preferPQ bool) []int {
	if preferPQ {
		return []int{GroupX25519MLKEM768, GroupX25519, GroupSecp256r1, GroupSecp384r1}
	}
	return []int{GroupX25519, GroupSecp256r1, GroupSecp384r1, GroupX25519MLKEM768}
}
