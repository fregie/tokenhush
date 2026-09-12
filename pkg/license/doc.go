// Package license verifies signed license tokens for read-only display.
//
// The open-source core never gates functionality on licensing; real paid
// capabilities live in the closed-source build. This package only proves a
// token's authenticity and reports its status, so that `tokenhush status` can
// render "Pro active (read-only)". It is deliberately isolated:
//
//   - it imports nothing outside the standard library (locked by
//     TestNoCoreLicenseGate),
//   - it never touches the network and reads exactly one caller-supplied file,
//   - no other core package except the CLI display seam may import it.
//
// # License file
//
// The file is a JSON object whose signature covers the canonical encoding
// returned by SigningInput:
//
//	{
//	  "version": 1,
//	  "key_id": "prod-2026-09",
//	  "license_id": "lic_example",
//	  "subject": "user@example.com",
//	  "features": ["pro"],
//	  "issued_at": "2026-09-11T00:00:00Z",
//	  "expires_at": "2027-09-11T00:00:00Z",
//	  "signature": "<base64url (no padding) Ed25519 signature>"
//	}
//
// The canonical signing input is newline-delimited, timestamps are reduced to
// Unix seconds, and features are sorted and comma-joined:
//
//	tokenhush-license-v1
//	key_id:prod-2026-09
//	license_id:lic_example
//	subject:user@example.com
//	features:pro
//	issued_at:1789603200
//	expires_at:1821139200
//
// # Validation rules
//
// A token renders the badge only when all of the following hold: it is valid
// JSON of at most MaxTokenSize bytes; version is exactly Version; key_id and
// license_id are non-empty; string/feature bounds hold; issued_at and
// expires_at parse as RFC 3339 with expires_at >= issued_at; key_id names an
// embedded key; the 64-byte Ed25519 signature verifies over SigningInput; and
// the current time is not later than expires_at + GracePeriod. A token whose
// issued_at lies in the future is accepted on purpose (clock-rollback
// tolerance). Every other outcome - absent, unreadable, malformed, tampered,
// unknown key, expired - yields no badge and no error detail at the CLI.
//
// Only Ed25519 public keys are ever embedded here. The private half is held by
// the closed-source license service; no private key may be committed to this
// repository.
package license
