// rules_rollback.go owns `tokenhush rules rollback`: it restores the previous
// verified pack that the frozen cache already holds, without any network call.
// The candidate is re-verified in a scratch sandbox BEFORE the active pointer
// moves, so a corrupt candidate can never displace the pack in force, and the
// anti-rollback mark is never touched — a rollback is a local repair, not a
// rewind of the stream's monotonic position.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/fregie/tokenhush/pkg/supply"
)

// errNoRollbackTarget is the typed failure of `rules rollback`: the cache
// holds no earlier pack that re-verifies, so there is nothing to restore.
var errNoRollbackTarget = errors.New("no previous verified pack is cached")

// cachedPack is one pack read back from the frozen cache layout.
type cachedPack struct {
	serial   uint64
	manifest []byte
	bundle   []byte
}

// rulesRollback runs `rules rollback`.
func rulesRollback(args []string, stdout, stderr io.Writer, seams rulesSeams) int {
	flags := flag.NewFlagSet("rules rollback", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: rules rollback: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	dataDir, err := seams.dataDir()
	if err != nil {
		return rulesFailure(stderr, "rollback", err)
	}
	cache := supply.NewRulesCache(dataDir)
	active, err := cache.ActiveSerial()
	if err != nil {
		return rulesFailure(stderr, "rollback", err)
	}
	if active == 0 {
		return rulesFailure(stderr, "rollback", errNoRollbackTarget)
	}
	target, err := previousVerifiedPack(dataDir, active, seams)
	if err != nil {
		return rulesFailure(stderr, "rollback", err)
	}
	// The pointer flips only now: re-storing the documents that are already in
	// the cache rewrites them atomically and points active at the candidate.
	if err := cache.Store(target.serial, target.manifest, target.bundle); err != nil {
		return rulesFailure(stderr, "rollback", err)
	}
	fmt.Fprintf(stdout, "rules rollback: restored the previous verified pack (serial %d).\n", target.serial)
	return exitOK
}

// previousVerifiedPack returns the highest cached serial below active that
// re-verifies under the cache path's own checks. A candidate that fails the
// sandbox is skipped in favour of an older one; the active pointer is never
// involved, so this is safe to run while another process serves traffic.
func previousVerifiedPack(dataDir string, active uint64, seams rulesSeams) (cachedPack, error) {
	serials, err := cachedPackSerials(dataDir, active)
	if err != nil {
		return cachedPack{}, err
	}
	for _, serial := range serials {
		candidate, err := readCachedPack(dataDir, serial)
		if err != nil {
			return cachedPack{}, err
		}
		if err := verifyCachedPack(candidate, seams); err != nil {
			continue
		}
		return candidate, nil
	}
	return cachedPack{}, errNoRollbackTarget
}

// cachedPackSerials lists the cached serials below active, highest first. The
// cache root is anchored through the cache's own RevocationsPath, so the
// frozen layout name is spelled once, in pkg/supply.
func cachedPackSerials(dataDir string, active uint64) ([]uint64, error) {
	entries, err := os.ReadDir(rulesCacheRoot(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var serials []uint64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		serial, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil || serial >= active || serial == 0 {
			continue
		}
		serials = append(serials, serial)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i] > serials[j] })
	return serials, nil
}

// rulesCacheRoot is the frozen <DataDir>/rules directory.
func rulesCacheRoot(dataDir string) string {
	return filepath.Dir(supply.NewRulesCache(dataDir).RevocationsPath())
}

// readCachedPack reads one cached pack's two documents from the frozen layout.
func readCachedPack(dataDir string, serial uint64) (cachedPack, error) {
	dir := filepath.Join(rulesCacheRoot(dataDir), strconv.FormatUint(serial, 10))
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return cachedPack{}, fmt.Errorf("read cached pack %d: %w", serial, err)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return cachedPack{}, fmt.Errorf("read cached pack %d: %w", serial, err)
	}
	return cachedPack{serial: serial, manifest: manifest, bundle: bundle}, nil
}

// verifyCachedPack re-runs the cache path's verification — the manifest
// signature, the manifest fields and every pack check, including the content
// floor, the serial match and the constant-time digest — in a scratch sandbox
// built from the same seams as the sync path. Startup is cache-only, so no
// network call exists on this path; the fetcher seam is still injected so a
// test can prove the count is zero.
func verifyCachedPack(candidate cachedPack, seams rulesSeams) error {
	scratch, err := os.MkdirTemp("", "tokenhush-rules-rollback-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := supply.NewRulesCache(scratch).Store(candidate.serial, candidate.manifest, candidate.bundle); err != nil {
		return err
	}
	syncer, err := supply.NewRulesSync(supply.RulesSyncConfig{
		DataDir: scratch, Fetcher: seams.fetcher(), Verifier: seams.verifier,
		LookupEnv: seams.lookupEnv, Now: seams.now,
	})
	if err != nil {
		return err
	}
	return syncer.Startup()
}
