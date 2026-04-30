package spqr

import (
	"bytes"
	"encoding/xml"
	"errors"
	"sync"
	"time"
)

type Limits struct {
	ItemMaxBytes       int64
	PublishesPerMinute int
}

func DefaultLimits() Limits {
	return Limits{
		ItemMaxBytes:       256 * 1024,
		PublishesPerMinute: 1,
	}
}

type RateChecker struct {
	mu           sync.Mutex
	lastByDevice map[string]time.Time
	limits       Limits
}

func NewRateChecker(l Limits) *RateChecker {
	return &RateChecker{
		lastByDevice: make(map[string]time.Time),
		limits:       l,
	}
}

func (rc *RateChecker) Allow(deviceKey string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	minGap := time.Minute / time.Duration(rc.limits.PublishesPerMinute)
	last, ok := rc.lastByDevice[deviceKey]
	now := time.Now()
	if ok && now.Sub(last) < minGap {
		return false
	}
	rc.lastByDevice[deviceKey] = now
	return true
}

func ValidateBundle(payload []byte, limits Limits) error {
	if len(payload) == 0 {
		return errors.New("spqr: bundle payload is empty")
	}
	if int64(len(payload)) > limits.ItemMaxBytes {
		return errors.New("spqr: bundle exceeds size limit")
	}

	dec := xml.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return errors.New("spqr: bundle is not valid XML")
	}
	start, ok := tok.(xml.StartElement)
	if !ok {
		return errors.New("spqr: bundle: expected start element")
	}
	if start.Name.Local != "bundle" {
		return errors.New("spqr: bundle: root element must be <bundle>")
	}
	ns := start.Name.Space
	if ns == "" {
		for _, a := range start.Attr {
			if a.Name.Local == "xmlns" {
				ns = a.Value
			}
		}
	}
	if ns != NSBundle {
		return errors.New("spqr: bundle: wrong namespace")
	}

	hasIdentity := false
	for {
		t, err := dec.Token()
		if err != nil {
			break
		}
		if s, ok := t.(xml.StartElement); ok {
			if s.Name.Local == "identity" {
				hasIdentity = true
				break
			}
		}
	}
	if !hasIdentity {
		return errors.New("spqr: bundle: missing <identity> child")
	}
	return nil
}
