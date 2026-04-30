package caps

import (
	"testing"

	"github.com/danielinux/xmppqr/internal/stanza"
)

func mustParse(s string) stanza.JID {
	j, err := stanza.Parse(s)
	if err != nil {
		panic(err)
	}
	return j
}

func TestRecordPresenceCapsElement(t *testing.T) {
	c := New()
	full := mustParse("bob@example.com/laptop")
	raw := []byte(`<presence from='bob@example.com/laptop'><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='https://example.org' ver='abc123'/></presence>`)

	if err := c.RecordPresence(full, raw); err != nil {
		t.Fatalf("RecordPresence: %v", err)
	}

	e, ok := c.Get(full)
	if !ok {
		t.Fatal("expected entry after RecordPresence, got none")
	}
	if e.Node != "https://example.org" {
		t.Errorf("node: got %q", e.Node)
	}
	if e.Ver != "abc123" {
		t.Errorf("ver: got %q", e.Ver)
	}

	c.PutFeatures(full, e.Node, e.Ver, []string{"urn:xmpp:foo+notify", "urn:xmpp:bar"})

	if !c.HasFeature(full, "urn:xmpp:foo+notify") {
		t.Error("HasFeature: expected true for urn:xmpp:foo+notify")
	}
	if c.HasFeature(full, "urn:xmpp:missing") {
		t.Error("HasFeature: expected false for urn:xmpp:missing")
	}
}

func TestForgetByPresenceUnavailable(t *testing.T) {
	c := New()
	full := mustParse("bob@example.com/laptop")
	c.PutFeatures(full, "n", "v", []string{"feat"})

	if _, ok := c.Get(full); !ok {
		t.Fatal("expected entry before Forget")
	}
	c.Forget(full)
	if _, ok := c.Get(full); ok {
		t.Fatal("expected no entry after Forget")
	}
}

func TestPutFeaturesAndHasFeature(t *testing.T) {
	c := New()
	full := mustParse("alice@example.com/desk")
	c.PutFeatures(full, "n", "v", []string{"urn:xmpp:omemo:2", "urn:xmpp:omemo:2+notify"})

	if !c.HasFeature(full, "urn:xmpp:omemo:2") {
		t.Error("expected omemo feature present")
	}
	if !c.HasFeature(full, "urn:xmpp:omemo:2+notify") {
		t.Error("expected omemo+notify feature present")
	}
	if c.HasFeature(full, "urn:xmpp:other") {
		t.Error("expected other feature absent")
	}
}

func TestBareJIDsWithFeatureMatching(t *testing.T) {
	c := New()
	bob1 := mustParse("bob@example.com/res1")
	bob2 := mustParse("bob@example.com/res2")
	carol := mustParse("carol@example.com/phone")

	c.PutFeatures(bob1, "n", "v", []string{"urn:xmpp:foo+notify"})
	c.PutFeatures(bob2, "n", "v", []string{"urn:xmpp:foo+notify"})
	c.PutFeatures(carol, "n", "v", []string{"urn:xmpp:foo+notify"})

	bobBare := mustParse("bob@example.com")
	matches := c.BareJIDsWithFeatureMatching(bobBare, "urn:xmpp:foo+notify")
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches for bob, got %d", len(matches))
	}
	for _, j := range matches {
		if j.Bare() != bobBare {
			t.Errorf("unexpected JID: %s", j)
		}
	}

	none := c.BareJIDsWithFeatureMatching(bobBare, "urn:xmpp:nothere")
	if len(none) != 0 {
		t.Errorf("expected 0 matches for absent feature, got %d", len(none))
	}
}
