package integ_test

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
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
	conn    *xtls.Conn
	ch      chan stanzaResult
	cancel  context.CancelFunc
	domain  string
	jid     stanza.JID
	smToken string
	smInH   uint32
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

	if _, err := conn.Write([]byte(`<active xmlns='urn:xmpp:csi:0'/>`)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send csi active: %w", err)
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

// dialForResume authenticates and restarts the stream but stops before bind,
// returning a Client ready to call ResumeSM.
func dialForResume(addr, domain, username, password string) (*Client, error) {
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
	bg := context.Background()

	streamOpen := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		domain,
	)
	if _, err := conn.Write([]byte(streamOpen)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send stream open: %w", err)
	}
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

// RawDisconnect closes the TCP connection immediately without a TLS shutdown,
// simulating a network drop.
func (c *Client) RawDisconnect() {
	c.cancel()
	_ = c.conn.Close()
}

// EnableSM sends <enable xmlns='urn:xmpp:sm:3'/> and reads <enabled>.
// Returns the resume token (empty when resume=false or server omits id).
func (c *Client) EnableSM(resume bool) (string, error) {
	resumeAttr := "false"
	if resume {
		resumeAttr = "true"
	}
	pkt := fmt.Sprintf(`<enable xmlns='urn:xmpp:sm:3' resume='%s'/>`, resumeAttr)
	if _, err := c.conn.Write([]byte(pkt)); err != nil {
		return "", fmt.Errorf("EnableSM write: %w", err)
	}
	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		return "", fmt.Errorf("EnableSM read: %w", err)
	}
	if start.Name.Local != "enabled" {
		return "", fmt.Errorf("EnableSM: expected <enabled>, got <%s>", start.Name.Local)
	}
	for _, a := range start.Attr {
		if a.Name.Local == "id" {
			c.smToken = a.Value
			return a.Value, nil
		}
	}
	return "", nil
}

// ResumeSM sends <resume previd='token' h='h'/> and expects <resumed> or <failed>.
func (c *Client) ResumeSM(token string, h uint32) error {
	pkt := fmt.Sprintf(`<resume xmlns='urn:xmpp:sm:3' previd='%s' h='%d'/>`, token, h)
	if _, err := c.conn.Write([]byte(pkt)); err != nil {
		return fmt.Errorf("ResumeSM write: %w", err)
	}
	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		return fmt.Errorf("ResumeSM read: %w", err)
	}
	if start.Name.Local == "failed" {
		return fmt.Errorf("ResumeSM: server returned <failed>")
	}
	if start.Name.Local != "resumed" {
		return fmt.Errorf("ResumeSM: expected <resumed>, got <%s>", start.Name.Local)
	}
	c.smToken = token
	return nil
}

// RequestAck sends <r xmlns='urn:xmpp:sm:3'/> and waits for <a h='..'/>.
func (c *Client) RequestAck() error {
	if _, err := c.conn.Write([]byte(`<r xmlns='urn:xmpp:sm:3'/>`)); err != nil {
		return fmt.Errorf("RequestAck write: %w", err)
	}
	start, _, err := c.NextStanzaWithTimeout(5 * time.Second)
	if err != nil {
		return fmt.Errorf("RequestAck read: %w", err)
	}
	if start.Name.Local != "a" {
		return fmt.Errorf("RequestAck: expected <a>, got <%s>", start.Name.Local)
	}
	return nil
}

// LastReceivedH returns the inbound stanza counter the client tracks.
func (c *Client) LastReceivedH() uint32 {
	return atomic.LoadUint32(&c.smInH)
}

func RegisterViaIBR(addr, domain, username, password string) error {
	tlsCtx, err := xtls.NewClientContext(nil, xtls.ClientOptions{
		InsecureSkipVerify: true,
		ServerName:         domain,
		MinVersion:         0x0303,
	})
	if err != nil {
		return fmt.Errorf("client tls context: %w", err)
	}
	defer tlsCtx.Close()

	conn, err := xtls.Dial("tcp", addr, tlsCtx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	dec := xmldec.NewDecoder(conn)
	bg := context.Background()

	streamOpen := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`,
		domain,
	)
	if _, err := conn.Write([]byte(streamOpen)); err != nil {
		return fmt.Errorf("send stream open: %w", err)
	}
	if _, err := dec.OpenStream(bg); err != nil {
		return fmt.Errorf("read server stream header: %w", err)
	}
	if _, _, err := dec.NextElement(); err != nil {
		return fmt.Errorf("read features: %w", err)
	}

	regIQ := fmt.Sprintf(
		`<iq id='ibr1' type='set'><query xmlns='jabber:iq:register'><username>%s</username><password>%s</password></query></iq>`,
		username, password,
	)
	if _, err := conn.Write([]byte(regIQ)); err != nil {
		return fmt.Errorf("send register IQ: %w", err)
	}

	start, _, err := dec.NextElement()
	if err != nil {
		return fmt.Errorf("read register response: %w", err)
	}
	if start.Name.Local != "iq" {
		return fmt.Errorf("register: expected <iq>, got <%s>", start.Name.Local)
	}
	iqType := ""
	for _, a := range start.Attr {
		if a.Name.Local == "type" {
			iqType = a.Value
			break
		}
	}
	if iqType != "result" {
		return fmt.Errorf("register: expected type=result, got %q", iqType)
	}
	return nil
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
