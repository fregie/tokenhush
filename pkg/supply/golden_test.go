// golden_test.go is the W5.7 golden-vector suite: it pins the two frozen
// signing-input projections (D6) to vectors that were validated against the
// legacy implementation, so one drifted byte — a reordered field, a lost sort,
// a dropped struct field — fails here by name.
//
// The vectors live in testdata/signing_vectors.json. Twelve of them are copies
// of the inline hex vectors in the legacy tree's own golden tests (an
// explicitly permitted DATA copy: no legacy .go file is ever copied), and the
// thirteenth is synthesized to cover what they do not: a command rule with all
// four command fields populated plus literals containing &, < and >, which
// pins json.Marshal's HTML escaping. Every entry carries a provenance field
// naming the legacy source path and the commit SHA captured at copy time.
package supply_test

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/fregie/tokenhush/pkg/supply"
)

const (
	goldenVectorsPath = "testdata/signing_vectors.json"
	// wantGoldenCount is EXACTLY the auditable vector count: 5 update vectors
	// plus 7 rules vectors plus the synthesized command vector. The two
	// byte-identical rules-revocations entries are deliberately NOT deduped,
	// so the count can be checked against the legacy sources.
	wantGoldenCount = 13
	// goldenLegacySHA is the legacy commit the copied vectors were read from
	// and the synthesized vector was produced against. It is asserted against
	// every entry's provenance, never assumed.
	goldenLegacySHA = "87512039ea82cddc5e8276e97b557264933bfd61"
)

// goldenVector mirrors one entry of testdata/signing_vectors.json.
type goldenVector struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Document   string          `json:"document_kind"`
	Doc        json.RawMessage `json:"document"`
	Expected   string          `json:"expected_signing_input_hex"`
	Provenance string          `json:"provenance"`
}

// signingInput recomputes the projection with the NEW structs. Dispatch is on
// the (kind, document_kind) pair, never on the vector's position.
func (v goldenVector) signingInput(t *testing.T) []byte {
	t.Helper()
	switch v.Kind + "/" + v.Document {
	case "update/manifest":
		var doc supply.UpdateManifestPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.UpdateManifestSigningInput(doc)
	case "update/revocations":
		var doc supply.UpdateRevocationsPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.UpdateRevocationsSigningInput(doc)
	case "update/keylist":
		var doc supply.UpdateKeyListPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.UpdateKeyListSigningInput(doc)
	case "rules/manifest":
		var doc supply.RulesManifestPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.RulesManifestSigningInput(doc)
	case "rules/revocations":
		var doc supply.RulesRevocationsPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.RulesRevocationsSigningInput(doc)
	case "rules/pack":
		var doc supply.RulesPackPayload
		decodeGoldenDoc(t, v, &doc)
		return supply.RulesPackSigningInput(doc)
	default:
		t.Fatalf("unknown vector kind %q/%q", v.Kind, v.Document)
		return nil
	}
}

func decodeGoldenDoc(t *testing.T, v goldenVector, doc any) {
	t.Helper()
	if err := json.Unmarshal(v.Doc, doc); err != nil {
		t.Fatalf("decode %s document: %v", v.Name, err)
	}
}

func loadGoldenVectors(t *testing.T) []goldenVector {
	t.Helper()
	raw, err := os.ReadFile(goldenVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", goldenVectorsPath, err)
	}
	var vectors []goldenVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("unmarshal %s: %v", goldenVectorsPath, err)
	}
	return vectors
}

// TestGoldenVectors recomputes every one of the 13 vectors with the new
// structs and asserts the signing input byte-for-byte.
func TestGoldenVectors(t *testing.T) {
	vectors := loadGoldenVectors(t)
	if len(vectors) != wantGoldenCount {
		t.Fatalf("vector count = %d, want exactly %d", len(vectors), wantGoldenCount)
	}

	names := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if names[v.Name] {
			t.Errorf("duplicate vector name %q", v.Name)
		}
		names[v.Name] = true
	}
	// Asserted BY NAME: the richest copied rules pack and the synthesized
	// command/HTML-escaping vector must both be present.
	for _, required := range []string{"rules-pack-rich", "rules-pack-command-all-fields"} {
		if !names[required] {
			t.Errorf("required vector %q is missing; got %v", required, names)
		}
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Expected == "" {
				t.Fatalf("%s: expected_signing_input_hex is empty", v.Name)
			}
			got := hex.EncodeToString(v.signingInput(t))
			if got != v.Expected {
				t.Errorf("%s: signing input drifted\n got: %s\nwant: %s", v.Name, got, v.Expected)
			}
		})
	}
}

// provenanceRe requires both halves of a provenance string: a .go source path
// and a 40-hex commit SHA.
var provenanceRe = regexp.MustCompile(`source=(?P<source>\S+\.go)\b.*\bsha=(?P<sha>[0-9a-f]{40})\b`)

// TestGoldenVectorProvenance asserts every entry names a legacy source path and
// a 40-hex commit SHA, and that the named path is NOT a file of this repo: that
// is what proves the vectors are a data copy, not a source copy.
func TestGoldenVectorProvenance(t *testing.T) {
	root := repoRoot(t)
	for _, v := range loadGoldenVectors(t) {
		if v.Provenance == "" {
			t.Errorf("%s: provenance is empty", v.Name)
			continue
		}
		match := provenanceRe.FindStringSubmatch(v.Provenance)
		if match == nil {
			t.Errorf("%s: provenance names no source .go path and 40-hex sha: %q", v.Name, v.Provenance)
			continue
		}
		source, sha := match[1], match[2]
		if sha != goldenLegacySHA {
			t.Errorf("%s: provenance sha %s is not the captured legacy commit %s", v.Name, sha, goldenLegacySHA)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(source))); err == nil {
			t.Errorf("%s: provenance source %s exists inside the rewrite repo; only data may be copied", v.Name, source)
		}
	}
}

// TestGoldenNoLegacySourceCopied asserts the repo holds no legacy Go source:
// no signing_input_golden_test.go anywhere, and no provenance source path
// materialised outside testdata/.
func TestGoldenNoLegacySourceCopied(t *testing.T) {
	root := repoRoot(t)
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".omo", "node_modules":
				return fs.SkipDir
			}
			return nil
		}
		if entry.Name() == "signing_input_golden_test.go" {
			t.Errorf("legacy Go source copied into the rewrite repo: %s", path)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
}

// repoRoot resolves the rewrite repository root from the package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}
