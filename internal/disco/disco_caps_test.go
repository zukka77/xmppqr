package disco

import (
	"strings"
	"testing"
)

func TestCapsElementContainsVerHash(t *testing.T) {
	f := DefaultServer()
	el := CapsElement(f)
	s := string(el)

	ver := f.VerHash()
	if !strings.Contains(s, ver) {
		t.Errorf("caps element missing ver hash %q; got: %s", ver, s)
	}
	if !strings.Contains(s, discoNode) {
		t.Errorf("caps element missing node URL %q; got: %s", discoNode, s)
	}
}
