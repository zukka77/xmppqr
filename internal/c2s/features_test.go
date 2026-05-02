package c2s

import (
	"strings"
	"testing"
)

// XEP-0440 channel-binding advertisement is required for modern clients
// (Conversations) to compute a matching SCRAM-PLUS channel-binding proof.
// Removing it sends them down a "guess" path that always fails not-authorized.
func TestBuildFeaturesAdvertisesChannelBinding(t *testing.T) {
	out := string(buildFeatures(&Session{}, true, false))

	if !strings.Contains(out, `<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>`) {
		t.Errorf("missing XEP-0440 sasl-channel-binding element; got: %s", out)
	}
	if !strings.Contains(out, `<channel-binding type='tls-exporter'/>`) {
		t.Errorf("missing tls-exporter type advertisement; got: %s", out)
	}

	// Order matters less than presence, but verify it sits inside the features element.
	if !strings.Contains(out, `<stream:features>`) || !strings.Contains(out, `</stream:features>`) {
		t.Errorf("malformed features wrapper; got: %s", out)
	}
}

func TestBuildFeaturesNoCBAdvertisementWhenSaslDisabled(t *testing.T) {
	out := string(buildFeatures(&Session{}, false, true))
	if strings.Contains(out, `sasl-channel-binding`) {
		t.Errorf("CB advertisement should only appear with sasl=true; got: %s", out)
	}
}
