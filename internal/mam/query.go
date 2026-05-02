package mam

import (
	"bytes"
	"context"
	"encoding/xml"
	"strconv"
	"time"

	"github.com/danielinux/xmppqr/internal/stanza"
	"github.com/danielinux/xmppqr/internal/storage"
)

// HandleMUCIQ processes urn:xmpp:mam:2 queries scoped to a MUC room.
// requesterFull is the full JID of the c2s session that sent the IQ.
// deliver is invoked once per message in the result set, with a fully
// formed <message> carrying a <result><forwarded><delay/></forwarded></result>.
// After all messages are delivered the function returns the marshalled
// IQ result containing <fin> + RSM.  Authorisation must be checked by
// the caller before invoking this method.
func (s *Service) HandleMUCIQ(ctx context.Context, iq *stanza.IQ, roomJID stanza.JID, requesterFull stanza.JID, deliver func([]byte) error) ([]byte, error) {
	pq, err := parseQueryPayload(iq.Payload)
	if err != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}

	var withJID *storage.JID
	if pq.filter.withJID != "" {
		w := pq.filter.withJID
		withJID = &w
	}

	results, err := s.store.QueryMUC(ctx, roomJID.Bare().String(), withJID, pq.filter.end, pq.filter.start, 0)
	if err != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeWait, Condition: stanza.ErrInternalServerError}
	}

	// RSM paging: locate anchor and slice.
	results = applyMUCRSM(results, pq.rsm)

	limit := pq.rsm.max
	complete := true
	if limit > 0 && len(results) > limit {
		results = results[:limit]
		complete = false
	}

	queryID := pq.filter.queryID

	for _, r := range results {
		msg := buildMUCResultMessage(requesterFull.String(), roomJID.Bare().String(), queryID, r)
		if err := deliver(msg); err != nil {
			s.logger.Warn("mam muc deliver result failed", "err", err)
		}
	}

	finPayload := buildMUCFin(results, complete)

	resp := &stanza.IQ{
		ID:   iq.ID,
		To:   iq.From,
		From: iq.To,
		Type: stanza.IQResult,
	}
	resp.Payload = finPayload
	return resp.Marshal()
}

func applyMUCRSM(all []*storage.MUCArchivedStanza, rsm rsmSet) []*storage.MUCArchivedStanza {
	if rsm.after != nil && *rsm.after != "" {
		for i, r := range all {
			if r.StanzaID == *rsm.after {
				return all[i+1:]
			}
		}
	}
	if rsm.before != nil && *rsm.before != "" {
		for i, r := range all {
			if r.StanzaID == *rsm.before {
				return all[:i]
			}
		}
	}
	return all
}

func buildMUCResultMessage(to, from, queryID string, r *storage.MUCArchivedStanza) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	msgStart := xml.StartElement{
		Name: xml.Name{Local: "message"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "to"}, Value: to},
			{Name: xml.Name{Local: "from"}, Value: from},
		},
	}
	enc.EncodeToken(msgStart)

	resultStart := xml.StartElement{
		Name: xml.Name{Space: nsMAM, Local: "result"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsMAM},
			{Name: xml.Name{Local: "id"}, Value: r.StanzaID},
		},
	}
	if queryID != "" {
		resultStart.Attr = append(resultStart.Attr, xml.Attr{Name: xml.Name{Local: "queryid"}, Value: queryID})
	}
	enc.EncodeToken(resultStart)

	fwdStart := xml.StartElement{
		Name: xml.Name{Local: "forwarded"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "urn:xmpp:forward:0"},
		},
	}
	enc.EncodeToken(fwdStart)

	delayStart := xml.StartElement{
		Name: xml.Name{Local: "delay"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "urn:xmpp:delay"},
			{Name: xml.Name{Local: "stamp"}, Value: r.TS.Format(time.RFC3339)},
		},
	}
	enc.EncodeToken(delayStart)
	enc.EncodeToken(delayStart.End())
	enc.Flush()

	buf.Write(stanza.EnsureClientNamespace(r.StanzaXML))

	enc.EncodeToken(fwdStart.End())
	enc.EncodeToken(resultStart.End())
	enc.EncodeToken(msgStart.End())
	enc.Flush()

	return buf.Bytes()
}

func buildMUCFin(results []*storage.MUCArchivedStanza, complete bool) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	completeStr := "false"
	if complete {
		completeStr = "true"
	}

	finStart := xml.StartElement{
		Name: xml.Name{Space: nsMAM, Local: "fin"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsMAM},
			{Name: xml.Name{Local: "complete"}, Value: completeStr},
		},
	}
	enc.EncodeToken(finStart)

	setStart := xml.StartElement{
		Name: xml.Name{Space: nsRSM, Local: "set"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: nsRSM}},
	}
	enc.EncodeToken(setStart)

	writeEl := func(local, val string) {
		el := xml.StartElement{Name: xml.Name{Local: local}}
		enc.EncodeToken(el)
		enc.EncodeToken(xml.CharData(val))
		enc.EncodeToken(el.End())
	}

	if len(results) > 0 {
		writeEl("first", results[0].StanzaID)
		writeEl("last", results[len(results)-1].StanzaID)
	}
	writeEl("count", strconv.Itoa(len(results)))

	enc.EncodeToken(setStart.End())
	enc.EncodeToken(finStart.End())
	enc.Flush()

	return buf.Bytes()
}

func (s *Service) HandleIQ(ctx context.Context, iq *stanza.IQ, ownerBare string, deliver func([]byte) error) ([]byte, error) {
	pq, err := parseQueryPayload(iq.Payload)
	if err != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeModify, Condition: stanza.ErrBadRequest}
	}

	var withJID *storage.JID
	if pq.filter.withJID != "" {
		w := pq.filter.withJID
		withJID = &w
	}

	results, err := s.store.Query(ctx, ownerBare, withJID, pq.filter.end, pq.filter.start, 0)
	if err != nil {
		return nil, &stanza.StanzaError{Type: stanza.ErrorTypeWait, Condition: stanza.ErrInternalServerError}
	}

	// RSM paging: locate anchor and slice.
	results = applyRSM(results, pq.rsm)

	limit := pq.rsm.max
	complete := true
	if limit > 0 && len(results) > limit {
		results = results[:limit]
		complete = false
	}

	queryID := pq.filter.queryID

	for _, r := range results {
		msg := buildResultMessage(iq.From, ownerBare, queryID, r)
		if err := deliver(msg); err != nil {
			s.logger.Warn("mam deliver result failed", "err", err)
		}
	}

	finPayload := buildFin(results, complete)

	resp := &stanza.IQ{
		ID:   iq.ID,
		To:   iq.From,
		From: iq.To,
		Type: stanza.IQResult,
	}
	resp.Payload = finPayload
	return resp.Marshal()
}

func applyRSM(all []*storage.ArchivedStanza, rsm rsmSet) []*storage.ArchivedStanza {
	if rsm.after != nil && *rsm.after != "" {
		for i, r := range all {
			if r.StanzaID == *rsm.after {
				return all[i+1:]
			}
		}
	}
	if rsm.before != nil && *rsm.before != "" {
		for i, r := range all {
			if r.StanzaID == *rsm.before {
				return all[:i]
			}
		}
	}
	return all
}

func buildResultMessage(to, from, queryID string, r *storage.ArchivedStanza) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	msgStart := xml.StartElement{
		Name: xml.Name{Local: "message"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "to"}, Value: to},
			{Name: xml.Name{Local: "from"}, Value: from},
		},
	}
	enc.EncodeToken(msgStart)

	resultStart := xml.StartElement{
		Name: xml.Name{Space: nsMAM, Local: "result"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsMAM},
			{Name: xml.Name{Local: "id"}, Value: r.StanzaID},
		},
	}
	if queryID != "" {
		resultStart.Attr = append(resultStart.Attr, xml.Attr{Name: xml.Name{Local: "queryid"}, Value: queryID})
	}
	enc.EncodeToken(resultStart)

	fwdStart := xml.StartElement{
		Name: xml.Name{Local: "forwarded"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "urn:xmpp:forward:0"},
		},
	}
	enc.EncodeToken(fwdStart)

	delayStart := xml.StartElement{
		Name: xml.Name{Local: "delay"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: "urn:xmpp:delay"},
			{Name: xml.Name{Local: "stamp"}, Value: r.TS.Format(time.RFC3339)},
		},
	}
	enc.EncodeToken(delayStart)
	enc.EncodeToken(delayStart.End())
	enc.Flush()

	buf.Write(stanza.EnsureClientNamespace(r.StanzaXML))

	enc.EncodeToken(fwdStart.End())
	enc.EncodeToken(resultStart.End())
	enc.EncodeToken(msgStart.End())
	enc.Flush()

	return buf.Bytes()
}

func buildFin(results []*storage.ArchivedStanza, complete bool) []byte {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	completeStr := "false"
	if complete {
		completeStr = "true"
	}

	finStart := xml.StartElement{
		Name: xml.Name{Space: nsMAM, Local: "fin"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "xmlns"}, Value: nsMAM},
			{Name: xml.Name{Local: "complete"}, Value: completeStr},
		},
	}
	enc.EncodeToken(finStart)

	setStart := xml.StartElement{
		Name: xml.Name{Space: nsRSM, Local: "set"},
		Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: nsRSM}},
	}
	enc.EncodeToken(setStart)

	writeEl := func(local, val string) {
		el := xml.StartElement{Name: xml.Name{Local: local}}
		enc.EncodeToken(el)
		enc.EncodeToken(xml.CharData(val))
		enc.EncodeToken(el.End())
	}

	if len(results) > 0 {
		writeEl("first", results[0].StanzaID)
		writeEl("last", results[len(results)-1].StanzaID)
	}
	writeEl("count", strconv.Itoa(len(results)))

	enc.EncodeToken(setStart.End())
	enc.EncodeToken(finStart.End())
	enc.Flush()

	return buf.Bytes()
}
