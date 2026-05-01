package s2s

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var oidXMPPAddr = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 5}
var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

func xmppAddrsFromCert(der []byte) ([]string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	var addrs []string

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSAN) {
			addrs = append(addrs, xmppAddrsFromSANExtension(ext.Value)...)
		}
	}

	if len(addrs) == 0 && cert.Subject.CommonName != "" {
		addrs = append(addrs, cert.Subject.CommonName)
	}

	return addrs, nil
}

func xmppAddrsFromSANExtension(raw []byte) []string {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return nil
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil
	}

	var addrs []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.UnmarshalWithParams(rest, &gn, "")
		if err != nil {
			break
		}
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
			continue
		}
		addr := parseOtherName(gn.Bytes)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func parseOtherName(data []byte) string {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(data, &oid)
	if err != nil || !oid.Equal(oidXMPPAddr) {
		return ""
	}
	var explicit asn1.RawValue
	if _, err := asn1.UnmarshalWithParams(rest, &explicit, "tag:0,explicit"); err != nil {
		return ""
	}
	var s string
	if _, err := asn1.Unmarshal(explicit.Bytes, &s); err != nil {
		return ""
	}
	return s
}

func certMatchesDomain(der []byte, domain string) (bool, error) {
	addrs, err := xmppAddrsFromCert(der)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if a == domain {
			return true, nil
		}
	}
	return false, nil
}
