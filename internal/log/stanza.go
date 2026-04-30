package log

import "regexp"

var stanzaRedactRe = regexp.MustCompile(`(<(?:body|response)[^>]*>)[^<]*(</(?:body|response)>)`)

func RedactStanza(b []byte) []byte {
	return stanzaRedactRe.ReplaceAll(b, []byte(`${1}[REDACTED]${2}`))
}
