package cli

import (
	"path/filepath"

	"github.com/fregie/tokenhush/pkg/license"
	"github.com/fregie/tokenhush/pkg/platform"
)

// licenseVerifier is the verification seam for the read-only Pro badge. The
// production value uses the Ed25519 public key embedded in pkg/license; tests
// inject a runtime-generated key pair. It is display-only: no core behavior
// branches on license state and a verified license unlocks no capability.
var licenseVerifier = license.DefaultVerifier()

// proLicenseBadge returns license.Badge when a valid license file exists at
// <platform config dir>/license.json, and "" otherwise. Absence, malformed
// input, tampering, an unknown key and expiry all collapse into "no badge";
// the cause is never returned or printed, so a rejected token leaks nothing.
//
// W6.3 owns the full `tokenhush status` view and must keep calling this
// function for the badge line instead of duplicating path resolution.
func proLicenseBadge() string {
	dir, err := platform.ConfigDir()
	if err != nil {
		return ""
	}
	return licenseVerifier.Badge(filepath.Join(dir, license.FileName))
}
