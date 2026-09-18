// manifest.go decodes and verifies the rules manifest and owns the OD-4 gate
// input. It is deliberately separate from payload.go: the payload structs
// freeze what a signature covers, this file freezes what the client accepts.
//
// The rules-manifest schema_version is the gate signal. Version 1 is the live
// schema and keeps the OD-4 gate closed; version 2 is the coordinated future
// schema that opens it and starts refusing command-bearing packs. Any other
// value is rejected outright rather than guessed at, so a corrupt, absent or
// future version can never silently arm the gate.
package supply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Typed rejections. Callers branch on them with errors.Is; no error text ever
// echoes untrusted document content.
var (
	// ErrSchemaVersion reports a rules-manifest schema_version that is
	// neither 1 (the live schema) nor 2 (the coordinated gate schema).
	ErrSchemaVersion = errors.New("supply: unsupported rules manifest schema version")
	// ErrMalformedDoc reports a document that is not a single, strict JSON
	// object of the expected shape.
	ErrMalformedDoc = errors.New("supply: malformed document")
	// ErrNotYetValid reports a document before its not_before time.
	ErrNotYetValid = errors.New("supply: document not yet valid")
	// ErrExpired reports a document past its expires time.
	ErrExpired = errors.New("supply: document expired")
)

// DecodeRulesManifest decodes one raw rules-manifest document. The document
// size cap is the rules cap; unknown fields and trailing data are rejected, so
// a typo cannot be silently accepted into the signed payload.
func DecodeRulesManifest(data []byte) (RulesManifestPayload, error) {
	var manifest RulesManifestPayload
	if err := CheckDocSize(DomainRulesManifest, data); err != nil {
		return RulesManifestPayload{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return RulesManifestPayload{}, fmt.Errorf("%w: %w", ErrMalformedDoc, err)
	}
	var extra any
	switch err := dec.Decode(&extra); err {
	case io.EOF:
		return manifest, nil
	case nil:
		return RulesManifestPayload{}, fmt.Errorf("%w: trailing data after the document", ErrMalformedDoc)
	default:
		return RulesManifestPayload{}, fmt.Errorf("%w: trailing data: %w", ErrMalformedDoc, err)
	}
}

// VerifyRulesManifest verifies a decoded rules manifest, in order: the Ed25519
// signature over the frozen projection, the freshness window, then the OD-4
// schema-version gate. It returns nil only when the document is authentic,
// fresh and carries an accepted schema version; the gate's open/closed verdict
// is read separately from the payload's schema_version.
func VerifyRulesManifest(manifest RulesManifestPayload, verifier Verifier, now time.Time) error {
	if verifier == nil {
		return fmt.Errorf("%w: no verifier", ErrWrongKey)
	}
	signature, err := DecodeSignature(manifest.Signature)
	if err != nil {
		return err
	}
	if err := verifier.Verify(DomainRulesManifest, manifest.KeyID, RulesManifestSigningInput(manifest), signature); err != nil {
		return err
	}
	if now.Before(manifest.NotBefore.Time()) {
		return fmt.Errorf("%w: rules manifest not_before %d", ErrNotYetValid, int64(manifest.NotBefore))
	}
	if now.After(manifest.Expires.Time()) {
		return fmt.Errorf("%w: rules manifest expired at %d", ErrExpired, int64(manifest.Expires))
	}
	_, err = SchemaVersionGate(manifest.SchemaVersion)
	return err
}

// SchemaVersionGate evaluates the OD-4 gate input: the schema_version reported
// by the rules manifest. Version 1 keeps the gate closed, version 2 opens it;
// every other value, including an absent (zero) one, is rejected with
// ErrSchemaVersion so the gate can only open on a version this build
// understands.
func SchemaVersionGate(v int) (open bool, err error) {
	switch v {
	case 1:
		return false, nil
	case 2:
		return true, nil
	default:
		return false, fmt.Errorf("%w: %d", ErrSchemaVersion, v)
	}
}
