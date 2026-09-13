package rules

// Strict JSON decoding: unknown fields, duplicate keys and trailing data are
// all rejected with typed errors, so a typo like "block" for "action" or a
// repeated "schema_version" can never be silently accepted.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// MarshalTree re-encodes the generic YAML tree as JSON for the shared strict
// decode path.
func MarshalTree(tree any) ([]byte, error) {
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot normalize document: %v", ErrParse, err)
	}
	return raw, nil
}

// DecodeConfigJSON decodes one JSON config document with duplicate-key
// pre-scan, DisallowUnknownFields and a trailing-data check.
func DecodeConfigJSON(data []byte) (*Config, error) {
	var cfg Config
	if err := decodeStrict(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// decodeStrict decodes one JSON document into v with duplicate-key pre-scan,
// DisallowUnknownFields and a trailing-data check. It is shared by the rule
// content decoder and the signed remote-pack decoder so both reject typos and
// repeated keys identically.
func decodeStrict(data []byte, v any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: document is not valid UTF-8", ErrParse)
	}
	if err := checkJSONDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return classifyDecodeError(err)
	}
	var extra any
	switch err := dec.Decode(&extra); {
	case err == io.EOF:
		return nil
	case err == nil:
		return fmt.Errorf("%w: unexpected data after the document", ErrParse)
	default:
		return classifyDecodeError(err)
	}
}

// checkJSONDuplicateKeys walks the token stream and rejects any object that
// repeats a key. encoding/json otherwise applies last-key-wins silently.
func checkJSONDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data after the JSON document", ErrParse)
	}
	return nil
}

// walkJSONValue consumes one complete JSON value, rejecting duplicate object
// keys at every nesting level.
func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return classifyDecodeError(err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return classifyDecodeError(err)
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", ErrParse)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: duplicate key %q", ErrParse, key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: unexpected delimiter %q", ErrParse, delim)
	}
	if _, err := dec.Token(); err != nil { // consume the matching close delim
		return classifyDecodeError(err)
	}
	return nil
}

// classifyDecodeError maps an encoding/json failure to a typed error:
// unknown fields become ErrUnknownField (and ErrParse), everything else is
// wrapped in ErrParse with the offending field or byte offset when known.
func classifyDecodeError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		field := typeErr.Field
		if field == "" {
			field = string(typeErr.Value)
		}
		return fmt.Errorf("%w: field %s: %v", ErrParse, field, err)
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Errorf("%w: %v (byte %d)", ErrParse, err, syntaxErr.Offset)
	}
	const unknownPrefix = "json: unknown field "
	if strings.HasPrefix(err.Error(), unknownPrefix) {
		name := strings.TrimPrefix(err.Error(), unknownPrefix)
		return fmt.Errorf("%w: %w: %s", ErrParse, ErrUnknownField, name)
	}
	return fmt.Errorf("%w: %v", ErrParse, err)
}
