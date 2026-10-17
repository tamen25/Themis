package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Decode rejects ambiguous JSON. Source payloads may retain their historical
// whitespace; signed envelope and policy callers can require canonical bytes.
func Decode(b []byte, out any) error {
	if len(b) > MaxFile || !utf8.Valid(b) {
		return errors.New("invalid JSON size or UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	nodes := 0
	if err := unique(d, 0, &nodes); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(out)
}

func unique(d *json.Decoder, depth int, nodes *int) error {
	*nodes++
	if depth > 48 || *nodes > 100000 {
		return errors.New("JSON nesting or node budget")
	}
	t, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	if t == nil {
		return errors.New("null JSON value is not admitted in an envelope")
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			name, ok := k.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			fold := strings.ToLower(name)
			if seen[fold] {
				return errors.New("duplicate JSON key")
			}
			seen[fold] = true
			if e = unique(d, depth+1, nodes); e != nil {
				return e
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err = unique(d, depth+1, nodes); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func decodeCanonical(b []byte, out any) error {
	if err := Decode(b, out); err != nil {
		return err
	}
	if !bytes.Equal(b, canonical(out)) {
		return errors.New("noncanonical envelope JSON")
	}
	return nil
}

func ReadPolicy(b []byte) (Policy, error) {
	var p Policy
	if len(b) > MaxManifest {
		return p, errors.New("trust policy too large")
	}
	if err := Decode(b, &p); err != nil {
		return p, err
	}
	// Policy is externally managed and may use ordinary JSON whitespace. Exact
	// names are nevertheless enforced by a round-trip object-key check.
	var original, normalized any
	if json.Unmarshal(b, &original) != nil || json.Unmarshal(canonical(p), &normalized) != nil || !bytes.Equal(canonical(original), canonical(normalized)) {
		return p, errors.New("trust policy requires exact fields and explicit values")
	}
	return p, p.Validate()
}
