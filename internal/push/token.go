package push

import (
	"bytes"
	"encoding/xml"
	"errors"
)

func extractDeviceToken(formXML []byte) (string, error) {
	if len(formXML) == 0 {
		return "", errors.New("empty form")
	}
	dec := xml.NewDecoder(bytes.NewReader(formXML))
	var inTargetField bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "field" {
				inTargetField = false
				for _, a := range t.Attr {
					if a.Name.Local == "var" && (a.Value == "device_token" || a.Value == "token") {
						inTargetField = true
					}
				}
			}
			if t.Name.Local == "value" && inTargetField {
				var v string
				if err := dec.DecodeElement(&v, &t); err == nil && v != "" {
					return v, nil
				}
			}
		case xml.EndElement:
			if t.Name.Local == "field" {
				inTargetField = false
			}
		}
	}
	return "", errors.New("device token not found in form")
}
