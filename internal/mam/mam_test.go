package mam

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage/memstore"
)

func newTestService() *Service {
	st := memstore.New()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(st.MAM, logger)
}

func archiveMsg(t *testing.T, svc *Service, owner, from, to, body string, dir int) {
	t.Helper()
	msg := &stanza.Message{ID: newID(), From: from, To: to, Type: "chat", Body: body}
	raw := []byte("<message from='" + from + "' to='" + to + "'><body>" + body + "</body></message>")
	if err := svc.Archive(context.Background(), owner, msg, dir, raw); err != nil {
		t.Fatalf("archive: %v", err)
	}
}

func runHandleIQ(t *testing.T, svc *Service, owner, payload string) ([][]byte, []byte) {
	t.Helper()
	iq := &stanza.IQ{
		ID:      "q1",
		From:    owner,
		To:      owner,
		Type:    stanza.IQSet,
		Payload: []byte(payload),
	}
	var results [][]byte
	deliver := func(raw []byte) error {
		cp := make([]byte, len(raw))
		copy(cp, raw)
		results = append(results, cp)
		return nil
	}
	resp, err := svc.HandleIQ(context.Background(), iq, owner, deliver)
	if err != nil {
		t.Fatalf("HandleIQ: %v", err)
	}
	return results, resp
}

func TestHandleIQ_NoFilter(t *testing.T) {
	svc := newTestService()
	owner := "alice@example.com"

	archiveMsg(t, svc, owner, "bob@example.com", owner, "hello", 0)
	archiveMsg(t, svc, owner, owner, "carol@example.com", "world", 1)
	archiveMsg(t, svc, owner, "dave@example.com", owner, "hey", 0)

	payload := `<query xmlns='urn:xmpp:mam:2' queryid='test1'/>`
	results, resp := runHandleIQ(t, svc, owner, payload)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !strings.Contains(string(resp), "complete='true'") && !strings.Contains(string(resp), `complete="true"`) {
		t.Fatalf("expected complete=true in fin: %s", resp)
	}
}

func TestHandleIQ_FilterWithJID(t *testing.T) {
	svc := newTestService()
	owner := "alice@example.com"

	archiveMsg(t, svc, owner, "bob@example.com", owner, "from bob", 0)
	archiveMsg(t, svc, owner, "carol@example.com", owner, "from carol", 0)
	archiveMsg(t, svc, owner, "bob@example.com", owner, "also bob", 0)

	payload := `<query xmlns='urn:xmpp:mam:2' queryid='wjid'>
		<x xmlns='jabber:x:data' type='submit'>
			<field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field>
			<field var='with'><value>bob@example.com</value></field>
		</x>
	</query>`
	results, _ := runHandleIQ(t, svc, owner, payload)

	if len(results) != 2 {
		t.Fatalf("expected 2 results filtered by with JID, got %d", len(results))
	}
	for _, r := range results {
		if !strings.Contains(string(r), "bob@example.com") {
			t.Fatalf("result doesn't mention bob: %s", r)
		}
	}
}

func TestHandleIQ_RSMPaging(t *testing.T) {
	svc := newTestService()
	owner := "alice@example.com"

	for i := 0; i < 5; i++ {
		archiveMsg(t, svc, owner, "bob@example.com", owner, "msg", 0)
		time.Sleep(time.Millisecond)
	}

	payload := `<query xmlns='urn:xmpp:mam:2' queryid='p1'>
		<set xmlns='http://jabber.org/protocol/rsm'>
			<max>2</max>
		</set>
	</query>`
	results1, resp1 := runHandleIQ(t, svc, owner, payload)

	if len(results1) != 2 {
		t.Fatalf("page 1: expected 2 results, got %d", len(results1))
	}
	if !strings.Contains(string(resp1), "complete='false'") && !strings.Contains(string(resp1), `complete="false"`) {
		t.Fatalf("page 1 should not be complete: %s", resp1)
	}

	// Extract last cursor from fin.
	lastCursor := extractLast(string(resp1))
	if lastCursor == "" {
		t.Fatalf("no last cursor in fin: %s", resp1)
	}

	payload2 := `<query xmlns='urn:xmpp:mam:2' queryid='p2'>
		<set xmlns='http://jabber.org/protocol/rsm'>
			<after>` + lastCursor + `</after>
		</set>
	</query>`
	results2, resp2 := runHandleIQ(t, svc, owner, payload2)

	if len(results2) != 3 {
		t.Fatalf("page 2: expected 3 remaining results, got %d", len(results2))
	}
	if !strings.Contains(string(resp2), "complete='true'") && !strings.Contains(string(resp2), `complete="true"`) {
		t.Fatalf("page 2 should be complete: %s", resp2)
	}
}

func extractLast(fin string) string {
	const open = "<last>"
	const close = "</last>"
	i := strings.Index(fin, open)
	if i < 0 {
		return ""
	}
	j := strings.Index(fin[i:], close)
	if j < 0 {
		return ""
	}
	return fin[i+len(open) : i+j]
}
