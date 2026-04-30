package disco

import (
	"encoding/xml"
	"testing"
)

func TestVerHashDeterminism(t *testing.T) {
	f := DefaultServer()
	h1 := f.VerHash()
	h2 := f.VerHash()
	if h1 != h2 {
		t.Fatalf("ver hash not deterministic: %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Fatal("empty ver hash")
	}
}

func TestVerHashChangesOnFeatureChange(t *testing.T) {
	f := DefaultServer()
	h1 := f.VerHash()

	f2 := DefaultServer()
	f2.Vars = append(f2.Vars, "urn:xmpp:test:extra")
	h2 := f2.VerHash()

	if h1 == h2 {
		t.Fatal("hash did not change after adding feature")
	}
}

func TestMarshalDiscoInfoRoundTrip(t *testing.T) {
	f := DefaultServer()
	raw := f.MarshalDiscoInfo("")

	type feature struct {
		Var string `xml:"var,attr"`
	}
	type identity struct {
		Category string `xml:"category,attr"`
		Type     string `xml:"type,attr"`
		Name     string `xml:"name,attr"`
	}
	type query struct {
		XMLName    xml.Name   `xml:"query"`
		Identities []identity `xml:"identity"`
		Features   []feature  `xml:"feature"`
	}

	var q query
	if err := xml.Unmarshal(raw, &q); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(q.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(q.Identities))
	}
	if q.Identities[0].Category != "server" {
		t.Errorf("identity category: got %q", q.Identities[0].Category)
	}
	if len(q.Features) != len(f.Vars) {
		t.Errorf("feature count: got %d, want %d", len(q.Features), len(f.Vars))
	}
}

func TestDefaultServerHasLegacyFeatures(t *testing.T) {
	f := DefaultServer()
	required := []string{
		"urn:ietf:params:xml:ns:xmpp-session",
		"jabber:iq:version",
		"jabber:iq:last",
		"urn:xmpp:time",
	}
	for _, ns := range required {
		found := false
		for _, v := range f.Vars {
			if v == ns {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing feature: %s", ns)
		}
	}
}

func TestMarshalDiscoInfoWithNode(t *testing.T) {
	f := DefaultServer()
	raw := f.MarshalDiscoInfo("http://example.com#test")

	type query struct {
		XMLName xml.Name `xml:"query"`
		Node    string   `xml:"node,attr"`
	}
	var q query
	if err := xml.Unmarshal(raw, &q); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if q.Node != "http://example.com#test" {
		t.Errorf("node attr: got %q", q.Node)
	}
}
