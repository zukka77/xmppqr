package integ_test

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	xtls "github.com/danielinux/xmppqr/internal/tls"
	xmldec "github.com/danielinux/xmppqr/internal/xml"
	"github.com/danielinux/xmppqr/internal/stanza"
)

var ErrTimeout = errors.New("read timeout")

type stanzaResult struct {
	start xml.StartElement
	raw   []byte
	err   error
}

type Client struct {
	conn   *xtls.Conn
	ch     chan stanzaResult
	cancel context.CancelFunc
	domain string
	jid    stanza.JID
}

func DialAndAuthDirectTLS(addr, domain, username, password string) (*Client, error) {
	ctx, err := xtls.NewClientContext(nil, xtls.ClientOptions{
		InsecureSkipVerify: true,
		ServerName:         domain,
		MinVersion:         0x0303,
	})
	if err != nil {
		return nil, fmt.Errorf("client tls context: %w", err)
	}
	defer ctx.Close()

	conn, err := xtls.Dial("tcp", addr, ctx)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	dec := xmldec.NewDecoder(conn)

	streamOpen := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		domain,
	)
	if _, err := conn.Write([]byte(streamOpen)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send stream open: %w", err)
	}

	bg := context.Background()
	if _, err := dec.OpenStream(bg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read server stream header: %w", err)
	}

	if _, _, err := dec.NextElement(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read features: %w", err)
	}

	plainPayload := base64.StdEncoding.EncodeToString(
		[]byte("\x00" + username + "\x00" + password),
	)
	authXML := fmt.Sprintf(
		`<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>%s</auth>`,
		plainPayload,
	)
	if _, err := conn.Write([]byte(authXML)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send auth: %w", err)
	}

	start, _, err := dec.NextElement()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	if start.Name.Local != "success" {
		conn.Close()
		return nil, fmt.Errorf("auth failed: got <%s>", start.Name.Local)
	}

	streamOpen2 := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		domain,
	)
	if _, err := conn.Write([]byte(streamOpen2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send stream restart: %w", err)
	}

	dec2 := xmldec.NewDecoder(conn)

	if _, err := dec2.OpenStream(bg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read post-auth stream header: %w", err)
	}

	if _, _, err := dec2.NextElement(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read post-auth features: %w", err)
	}

	bindIQ := `<iq id='b1' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>`
	if _, err := conn.Write([]byte(bindIQ)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send bind: %w", err)
	}

	bindStart, bindRaw, err := dec2.NextElement()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read bind result: %w", err)
	}
	if bindStart.Name.Local != "iq" {
		conn.Close()
		return nil, fmt.Errorf("bind: expected <iq>, got <%s>", bindStart.Name.Local)
	}

	fullJIDStr := extractJIDFromBind(bindRaw)
	if fullJIDStr == "" {
		conn.Close()
		return nil, fmt.Errorf("bind: could not parse JID from result")
	}

	fullJID, err := stanza.Parse(fullJIDStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind: invalid JID %q: %w", fullJIDStr, err)
	}

	readerCtx, readerCancel := context.WithCancel(context.Background())
	ch := make(chan stanzaResult, 64)
	go func() {
		defer close(ch)
		for {
			s, raw, rerr := dec2.NextElement()
			select {
			case ch <- stanzaResult{s, raw, rerr}:
			case <-readerCtx.Done():
				return
			}
			if rerr != nil {
				return
			}
		}
	}()

	return &Client{
		conn:   conn,
		ch:     ch,
		cancel: readerCancel,
		domain: domain,
		jid:    fullJID,
	}, nil
}

func (c *Client) Send(raw []byte) error {
	_, err := c.conn.Write(raw)
	return err
}

func (c *Client) NextStanza() (xml.StartElement, []byte, error) {
	r, ok := <-c.ch
	if !ok {
		return xml.StartElement{}, nil, errors.New("client: reader closed")
	}
	return r.start, r.raw, r.err
}

func (c *Client) NextStanzaWithTimeout(d time.Duration) (xml.StartElement, []byte, error) {
	select {
	case r, ok := <-c.ch:
		if !ok {
			return xml.StartElement{}, nil, errors.New("client: reader closed")
		}
		return r.start, r.raw, r.err
	case <-time.After(d):
		return xml.StartElement{}, nil, ErrTimeout
	}
}

func (c *Client) JID() stanza.JID { return c.jid }

func (c *Client) Close() error {
	c.cancel()
	return c.conn.Close()
}

func extractJIDFromBind(raw []byte) string {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	inJID := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "jid" {
				inJID = true
			}
		case xml.EndElement:
			if t.Name.Local == "jid" {
				inJID = false
			}
		case xml.CharData:
			if inJID {
				return strings.TrimSpace(string(t))
			}
		}
	}
}
