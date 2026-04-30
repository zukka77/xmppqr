package spqr

import (
	"fmt"
	"testing"
	"time"
)

var defaultLimits = DefaultLimits()

func TestBundleWithinCap(t *testing.T) {
	payload := []byte(fmt.Sprintf(`<bundle xmlns="%s"><identity key="abc"/></bundle>`, NSBundle))
	if err := ValidateBundle(payload, defaultLimits); err != nil {
		t.Errorf("expected ok, got: %v", err)
	}
}

func TestBundleExceedsCap(t *testing.T) {
	big := make([]byte, 300*1024)
	for i := range big {
		big[i] = 'x'
	}
	if err := ValidateBundle(big, defaultLimits); err == nil {
		t.Error("expected error for oversized bundle")
	}
}

func TestBundleMissingIdentity(t *testing.T) {
	payload := []byte(fmt.Sprintf(`<bundle xmlns="%s"><keys><key id="1"/></keys></bundle>`, NSBundle))
	if err := ValidateBundle(payload, defaultLimits); err == nil {
		t.Error("expected error for missing <identity>")
	}
}

func TestRateCheckerRejectsThenAllows(t *testing.T) {
	l := Limits{ItemMaxBytes: 256 * 1024, PublishesPerMinute: 60}
	rc := NewRateChecker(l)

	if !rc.Allow("dev1") {
		t.Fatal("first Allow should succeed")
	}
	if rc.Allow("dev1") {
		t.Fatal("second immediate Allow should be rejected")
	}

	rc.mu.Lock()
	rc.lastByDevice["dev1"] = time.Now().Add(-2 * time.Second)
	rc.mu.Unlock()

	if !rc.Allow("dev1") {
		t.Fatal("Allow after gap should succeed")
	}
}

func TestSPQROnlyModeRejectsPlain(t *testing.T) {
	policy := DomainPolicy{SPQROnlyMode: true}
	msg := []byte(`<message to="bob@example.com"><body>hi</body></message>`)
	if err := EnforceMessagePolicy(msg, policy); err == nil {
		t.Error("expected policy-violation for plain message")
	}
}

func TestSPQROnlyModeAcceptsEnvelope(t *testing.T) {
	policy := DomainPolicy{SPQROnlyMode: true}
	msg := []byte(fmt.Sprintf(`<message to="bob@example.com"><spqr xmlns="%s"/></message>`, NSEnvelope))
	if err := EnforceMessagePolicy(msg, policy); err != nil {
		t.Errorf("expected ok for message with spqr envelope, got: %v", err)
	}
}
