// apply_e2e_test.go is the W5.8 end-to-end apply suite. It drives the FULL
// update apply through the public Update entry point -- the D17 routing, the
// signed sequence, the artifact download, the two-phase replace and the
// anti-rollback advance -- against the stub issuer and a temp install
// directory, and it asserts the on-disk outcome rather than any internal step:
// the replaced file's bytes ARE the artifact's bytes, the mark advanced, the
// install stays recoverable, and a kill injected between the two committing
// renames is repaired by Recover into a runnable binary.
//
// Nothing here is a package-level unit stub: the issuer signs real documents
// with an in-process Ed25519 key, the production verification path verifies
// them, and the install is a real file tree.
package supply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// TestApplyE2E is the QA suite of W5.8.
func TestApplyE2E(t *testing.T) {
	t.Run("a full apply replaces the binary, advances the mark and stays recoverable", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)

		result, err := h.newUpdater(nil).Update(context.Background(), false)
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if result.Status != UpdateInstalled || result.Serial != updateTestSerial || result.Version != updateTestVersion {
			t.Fatalf("Update = %+v, want installed serial %d version %s", result, updateTestSerial, updateTestVersion)
		}

		// The replaced file's bytes equal the artifact bytes, EXACTLY, and the
		// replacement really happened (the previous binary was different).
		got, err := os.ReadFile(h.target)
		if err != nil {
			t.Fatalf("read the replaced binary: %v", err)
		}
		if !bytes.Equal(got, updateTestArtifact) {
			t.Fatalf("replaced binary bytes = %q, want the artifact bytes %q", got, updateTestArtifact)
		}
		if bytes.Equal(got, updateTestOriginal) {
			t.Fatalf("replaced binary still holds the previous release %q", got)
		}
		info, err := os.Stat(h.target)
		if err != nil {
			t.Fatalf("stat the replaced binary: %v", err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("replaced binary is not executable: %v", info.Mode().Perm())
		}

		// The high-water mark advanced and no staging survives the commit.
		mark, err := NewUpdateHighWater(h.dataDir)
		if err != nil {
			t.Fatalf("NewUpdateHighWater: %v", err)
		}
		if got := mark.Current(); got != updateTestSerial {
			t.Fatalf("high-water = %d, want %d", got, updateTestSerial)
		}
		h.assertNoStaging()

		// The resulting state is recoverable: Recover is a no-op on a settled
		// install, and a fresh updater (a restart) reads the persisted mark.
		if recovered, err := Recover(h.target); err != nil || recovered != RecoveryNone {
			t.Fatalf("Recover after a successful apply = (%q, %v), want (none, nil)", recovered, err)
		}
		again, err := h.newUpdater(nil).Update(context.Background(), false)
		if err != nil {
			t.Fatalf("Update after a restart: %v", err)
		}
		if again.Status != UpdateUpToDate || again.Serial != updateTestSerial {
			t.Fatalf("Update after a restart = %+v, want up-to-date serial %d", again, updateTestSerial)
		}
	})

	t.Run("a kill between the two renames is repaired into a runnable binary", func(t *testing.T) {
		h := newUpdateHarness(t)
		h.publish(nil)
		updater := h.newUpdater(nil)
		updater.kill = func(step string) error {
			if step == stepBackedUp {
				return errInjectedCrash
			}
			return nil
		}

		if _, err := updater.Update(context.Background(), false); !errors.Is(err, errInjectedCrash) {
			t.Fatalf("Update with a kill between the two renames = %v, want the injected crash", err)
		}

		// The death leaves exactly the half-applied state the journal names:
		// the target moved to last-known-good, the candidate still staged.
		if fileExists(h.target) {
			t.Fatalf("target still present between the two renames")
		}
		if !fileExists(h.target+candidateSuffix) || !fileExists(h.target+journalSuffix) {
			t.Fatalf("candidate or journal missing between the two renames")
		}

		recovered, err := Recover(h.target)
		if err != nil {
			t.Fatalf("Recover after the interrupted apply: %v", err)
		}
		if recovered != RecoveryCompleted {
			t.Fatalf("Recover = %q, want completed", recovered)
		}
		got := runnable(t, h.target)
		if !bytes.Equal(got, updateTestArtifact) {
			t.Fatalf("recovered binary bytes = %q, want the artifact bytes %q", got, updateTestArtifact)
		}

		// Recover is idempotent afterwards.
		again, err := Recover(h.target)
		if err != nil || again != RecoveryNone {
			t.Fatalf("second Recover = (%q, %v), want (none, nil)", again, err)
		}

		// The interrupted apply never advanced the mark, so the same serial is
		// still retryable instead of being treated as a replay.
		mark, err := NewUpdateHighWater(h.dataDir)
		if err != nil {
			t.Fatalf("NewUpdateHighWater: %v", err)
		}
		if got := mark.Current(); got != 0 {
			t.Fatalf("high-water = %d after an interrupted apply, want 0", got)
		}
	})
}
