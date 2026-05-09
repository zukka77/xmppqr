package pubsub

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestCaptureInnerXMLDoesNotDuplicateDefaultNamespace(t *testing.T) {
	dec := xml.NewDecoder(strings.NewReader(
		`<item><devicelist xmlns='urn:xmppqr:x3dhpq:devicelist:0' version='1'><device id='1'/></devicelist></item>`,
	))

	for {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("failed to reach <item>: %v", err)
		}
		start, ok := tok.(xml.StartElement)
		if ok && start.Name.Local == "item" {
			break
		}
	}

	payload, err := captureInnerXML(dec)
	if err != nil {
		t.Fatalf("captureInnerXML: %v", err)
	}
	got := string(payload)

	if strings.Contains(
		got,
		`<devicelist xmlns="urn:xmppqr:x3dhpq:devicelist:0" xmlns="urn:xmppqr:x3dhpq:devicelist:0"`,
	) {
		t.Fatalf("expected root element without duplicate default namespace, got %q", got)
	}
	if !strings.Contains(got, `<device xmlns="urn:xmppqr:x3dhpq:devicelist:0" id="1"></device>`) {
		t.Fatalf("expected payload to remain namespaced, got %q", got)
	}
}
