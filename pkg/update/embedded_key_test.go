package update

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// updateKeyPublic is the production update signing key. It is deliberately NOT
// embedded: it may only enter a client through a root-signed key list, so the
// root's compromise surface stays offline. This literal doubles as a guard that
// an accidental embed fails here.
var updateKeyPublic = ed25519.PublicKey{
	0xe3, 0x4b, 0x3b, 0x02, 0xb5, 0x9a, 0x3d, 0xc4,
	0xa3, 0x88, 0x80, 0x74, 0xa4, 0x94, 0xef, 0x80,
	0x76, 0xb6, 0x12, 0xde, 0x1a, 0xe1, 0x8f, 0xcc,
	0xb7, 0x1f, 0xef, 0x0b, 0xfd, 0xdd, 0xda, 0xd5,
}

// TestEmbeddedRootKeyIsTheProductionRoot locks the trust root: the embedded
// key_id and public bytes must equal this checked-in expectation. The literal
// is independent of rootPublic so a placeholder regression or an accidental key
// swap fails here instead of shipping silently.
func TestEmbeddedRootKeyIsTheProductionRoot(t *testing.T) {
	want := ed25519.PublicKey{
		0xe9, 0x7d, 0xd2, 0xcf, 0xed, 0x5c, 0xf6, 0xee,
		0x62, 0xc9, 0x20, 0x24, 0x1c, 0xc4, 0x91, 0xe0,
		0xcb, 0xf1, 0x3f, 0x2f, 0x35, 0xd8, 0x55, 0x7b,
		0x92, 0x3a, 0xea, 0x77, 0xe1, 0xc7, 0x66, 0xf4,
	}
	roots := DefaultRoots()
	if len(roots) != 1 {
		t.Fatalf("DefaultRoots() has %d entries, want exactly 1", len(roots))
	}
	if got := roots[0].ID; got != "root-2026-09" {
		t.Errorf("DefaultRoots()[0].ID = %q, want %q", got, "root-2026-09")
	}
	if got := roots[0].Public; !bytes.Equal(got, want) {
		t.Errorf("DefaultRoots()[0].Public = %x, want %x", got, want)
	}
	if got := rootKeyID; got != "root-2026-09" {
		t.Errorf("rootKeyID = %q, want %q", got, "root-2026-09")
	}
}

// TestUpdateKeyIsNotEmbedded guards the trust separation: the online update key
// must reach a client only through a root-signed key list, never compiled in.
func TestUpdateKeyIsNotEmbedded(t *testing.T) {
	for _, root := range DefaultRoots() {
		if bytes.Equal(root.Public, updateKeyPublic) {
			t.Fatalf("DefaultRoots() must not embed the update key %q", root.ID)
		}
	}
}
