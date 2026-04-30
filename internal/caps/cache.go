// Package caps implements a trust-on-first-use XEP-0115 caps cache.
// It does NOT verify caps hashes via disco#info; features are accepted as
// advertised via PutFeatures. Production implementations should query
// disco#info and verify the sha-1 ver hash before storing features.
package caps

import (
	"bytes"
	"encoding/xml"
	"sync"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
)

const nsCaps = "http://jabber.org/protocol/caps"

type Entry struct {
	Node      string
	Ver       string
	Features  []string
	UpdatedAt time.Time
}

type Cache struct {
	mu    sync.RWMutex
	byJID map[string]*Entry
}

func New() *Cache {
	return &Cache{byJID: make(map[string]*Entry)}
}

func (c *Cache) RecordPresence(fromFullJID stanza.JID, presenceRaw []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(presenceRaw))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == "c" && t.Name.Space == nsCaps {
				var node, ver string
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "node":
						node = a.Value
					case "ver":
						ver = a.Value
					}
				}
				if node == "" || ver == "" {
					return nil
				}
				c.mu.Lock()
				key := fromFullJID.String()
				e := c.byJID[key]
				if e == nil {
					e = &Entry{}
					c.byJID[key] = e
				}
				e.Node = node
				e.Ver = ver
				e.UpdatedAt = time.Now()
				c.mu.Unlock()
				return nil
			}
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

func (c *Cache) PutFeatures(fromFullJID stanza.JID, node, ver string, features []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := fromFullJID.String()
	cp := make([]string, len(features))
	copy(cp, features)
	c.byJID[key] = &Entry{
		Node:      node,
		Ver:       ver,
		Features:  cp,
		UpdatedAt: time.Now(),
	}
}

func (c *Cache) Get(fullJID stanza.JID) (*Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byJID[fullJID.String()]
	return e, ok
}

func (c *Cache) HasFeature(fullJID stanza.JID, feature string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byJID[fullJID.String()]
	if !ok {
		return false
	}
	for _, f := range e.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// BareJIDsWithFeature returns all full JIDs in the cache whose Features contain feature.
func (c *Cache) BareJIDsWithFeature(feature string) []stanza.JID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []stanza.JID
	for key, e := range c.byJID {
		for _, f := range e.Features {
			if f == feature {
				j, err := stanza.Parse(key)
				if err == nil {
					out = append(out, j)
				}
				break
			}
		}
	}
	return out
}

// BareJIDsWithFeatureMatching returns full JIDs whose bare JID matches bare and whose
// Features contain feature.
func (c *Cache) BareJIDsWithFeatureMatching(bare stanza.JID, feature string) []stanza.JID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []stanza.JID
	for key, e := range c.byJID {
		j, err := stanza.Parse(key)
		if err != nil {
			continue
		}
		if j.Bare() != bare.Bare() {
			continue
		}
		for _, f := range e.Features {
			if f == feature {
				out = append(out, j)
				break
			}
		}
	}
	return out
}

func (c *Cache) Forget(fullJID stanza.JID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byJID, fullJID.String())
}
