package log

import (
	"bytes"
	"testing"
)

func TestRedactStanzaBody(t *testing.T) {
	input := []byte(`<message><body>Hello World</body></message>`)
	got := RedactStanza(input)
	if bytes.Contains(got, []byte("Hello World")) {
		t.Error("body content should be redacted")
	}
	if !bytes.Contains(got, []byte("[REDACTED]")) {
		t.Error("expected [REDACTED] placeholder")
	}
	if !bytes.Contains(got, []byte("<body>")) || !bytes.Contains(got, []byte("</body>")) {
		t.Error("body tags should be preserved")
	}
	if !bytes.Contains(got, []byte("<message>")) {
		t.Error("surrounding elements should be preserved")
	}
}

func TestRedactStanzaResponse(t *testing.T) {
	input := []byte(`<auth><response>dXNlcjpwYXNz</response></auth>`)
	got := RedactStanza(input)
	if bytes.Contains(got, []byte("dXNlcjpwYXNz")) {
		t.Error("response content should be redacted")
	}
	if !bytes.Contains(got, []byte("<response>")) {
		t.Error("response tag should be preserved")
	}
}

func TestRedactStanzaBodyWithAttrs(t *testing.T) {
	input := []byte(`<body xml:lang="en">Secret</body>`)
	got := RedactStanza(input)
	if bytes.Contains(got, []byte("Secret")) {
		t.Error("body content should be redacted")
	}
	if !bytes.Contains(got, []byte(`xml:lang="en"`)) {
		t.Error("attributes should be preserved")
	}
}

func TestRedactStanzaNoMatch(t *testing.T) {
	input := []byte(`<presence><show>away</show></presence>`)
	got := RedactStanza(input)
	if !bytes.Equal(input, got) {
		t.Error("non-matching stanza should be byte-identical")
	}
}

func TestRedactStanzaEmptyBody(t *testing.T) {
	input := []byte(`<body></body>`)
	got := RedactStanza(input)
	if !bytes.Contains(got, []byte("<body>")) {
		t.Error("empty body tags should be preserved")
	}
}
