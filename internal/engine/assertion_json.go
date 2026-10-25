package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Reject ambiguous duplicate keys and preserve exact numeric identity instead
// of rounding object IDs through float64. Depth and number lengths are bounded.
func decodeAssertionJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := decodeValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return v, nil
}

func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("JSON nesting exceeds 64")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			v := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				s, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				if _, exists := v[s]; exists {
					return nil, fmt.Errorf("duplicate key")
				}
				value, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				v[s] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("invalid object")
			}
			return v, nil
		case '[':
			v := make([]any, 0)
			for d.More() {
				value, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				v = append(v, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("invalid array")
			}
			return v, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter")
		}
	case json.Number:
		if len(t) > 128 {
			return nil, fmt.Errorf("number exceeds 128 characters")
		}
		return normalizeNumber(string(t)), nil
	default:
		return token, nil
	}
}

type exactNumber string

// Represent decimal numbers as coefficient*10^exponent without expanding the
// exponent. This equates 1, 1.0 and 1e0 without losing large integer precision.
func normalizeNumber(s string) exactNumber {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	exponent := new(big.Int)
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent.SetString(strings.TrimPrefix(s[i+1:], "+"), 10)
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(s)-i-1)))
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return exactNumber("0")
	}
	trimmed := strings.TrimRight(s, "0")
	exponent.Add(exponent, big.NewInt(int64(len(s)-len(trimmed))))
	if negative {
		trimmed = "-" + trimmed
	}
	return exactNumber(trimmed + "e" + exponent.String())
}
