// Size guard: the 250-pure-LOC ceiling keeps every production file small
// enough to hold in one head. It counts strict pure LOC: blank lines and
// comment-only lines are excluded, every other line counts, including a lone
// closing brace and the package clause. Test files, testdata, generated files,
// .omo/ plan state and vendored code are not production code at all.
package guards

import (
	"fmt"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// maxPureLOC is the per-file ceiling for production Go files. A file above it
// is split, not excused.
const maxPureLOC = 250

// pureLOC counts the strict pure LOC of src: blank lines and comment-only
// lines are excluded, while every other line counts, including a lone closing
// brace and the package clause. A line counts when it contains at least one
// token that is not a comment and not an automatically inserted newline
// semicolon.
func pureLOC(src []byte) (int, error) {
	parseSet := token.NewFileSet()
	if _, err := parser.ParseFile(parseSet, "pureloc.go", src, parser.ParseComments); err != nil {
		return 0, fmt.Errorf("pure LOC: parse: %w", err)
	}

	scanSet := token.NewFileSet()
	tf := scanSet.AddFile("pureloc.go", scanSet.Base(), len(src))
	var s scanner.Scanner
	s.Init(tf, src, nil, scanner.ScanComments)
	lines := map[int]bool{}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT || (tok == token.SEMICOLON && lit == "\n") {
			continue
		}
		lines[tf.Line(pos)] = true
	}
	return len(lines), nil
}

// isProductionFile reports whether a repo-relative slash path is subject to
// the ceiling. Test files, anything under a testdata element, generated files,
// .omo/ plan state and vendored code are not production code. head is the
// file's first bytes, used for the generated marker.
func isProductionFile(rel string, head []byte) bool {
	rel = filepath.ToSlash(rel)
	if strings.HasSuffix(filepath.Base(rel), "_test.go") {
		return false
	}
	for _, elem := range strings.Split(rel, "/") {
		if elem == "testdata" {
			return false
		}
	}
	if strings.HasPrefix(rel, ".omo/") || strings.Contains(rel, "/vendor/") {
		return false
	}
	text := string(head)
	if strings.Contains(text, "Code generated") && strings.Contains(text, "DO NOT EDIT") {
		return false
	}
	return true
}

// sizeViolations walks root and returns one sorted message per production Go
// file that exceeds maxPureLOC, plus the number of production files scanned.
// .git and .omo directories are not walked.
func sizeViolations(root string) (offenders []string, scanned int, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".omo" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		head := src
		if len(head) > 2*1024 {
			head = head[:2*1024]
		}
		if !isProductionFile(rel, head) {
			return nil
		}
		loc, err := pureLOC(src)
		if err != nil {
			return fmt.Errorf("size guard: %s: %w", rel, err)
		}
		scanned++
		if loc > maxPureLOC {
			offenders = append(offenders, fmt.Sprintf("%s (%d pure LOC > %d)", rel, loc, maxPureLOC))
		}
		return nil
	})
	if walkErr != nil {
		return nil, scanned, walkErr
	}
	sort.Strings(offenders)
	return offenders, scanned, nil
}

// sizedSource returns a parseable source file with exactly n strict pure LOC:
// one package clause plus n-1 single-line variable declarations, separated by
// blank lines. The package clause and the declarations each count once; the
// blanks never count.
func sizedSource(n int) []byte {
	lines := make([]string, 0, 2*n+2)
	lines = append(lines, "package probe", "")
	for i := 0; i < n-1; i++ {
		lines = append(lines, "", fmt.Sprintf("var v%d = %d", i, i))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func TestSizeGuardPureLocCounting(t *testing.T) {
	t.Run("code lines count once each", func(t *testing.T) {
		got, err := pureLOC(sizedSource(260))
		if err != nil {
			t.Fatalf("pureLOC(260 code lines): %v", err)
		}
		if got != 260 {
			t.Errorf("pureLOC(260 code lines) = %d, want 260", got)
		}
	})

	t.Run("blank and comment lines do not count", func(t *testing.T) {
		lines := []string{"package probe", "", "// leading comment"}
		for i := 0; i < 260; i++ {
			lines = append(lines, fmt.Sprintf("var v%d = %d", i, i), "", fmt.Sprintf("// comment %d", i), "")
		}
		got, err := pureLOC([]byte(strings.Join(lines, "\n") + "\n"))
		if err != nil {
			t.Fatalf("pureLOC(260 declarations with blanks and comments): %v", err)
		}
		if got != 261 {
			t.Errorf("pureLOC(260 declarations with blanks and comments) = %d, want 261 (package clause plus 260 declarations)", got)
		}
	})

	t.Run("blank and comment lines add nothing", func(t *testing.T) {
		src := []byte("package probe\n\n// nothing to count here\n\n// and nothing here\n")
		got, err := pureLOC(src)
		if err != nil {
			t.Fatalf("pureLOC(comment-only body): %v", err)
		}
		if got != 1 {
			t.Errorf("pureLOC(comment-only body) = %d, want 1 for the package clause", got)
		}
	})

	t.Run("package, func header and lone brace count", func(t *testing.T) {
		src := []byte("package p\n\n// a comment line\n\nfunc f() {\n}\n")
		got, err := pureLOC(src)
		if err != nil {
			t.Fatalf("pureLOC(package, func and lone brace): %v", err)
		}
		if got != 3 {
			t.Errorf("pureLOC(package, func and lone brace) = %d, want 3", got)
		}
	})

	t.Run("a lone closing brace counts once", func(t *testing.T) {
		src := []byte("package p\n\nfunc f() {\n\n\t// body comment\n\n}\n")
		got, err := pureLOC(src)
		if err != nil {
			t.Fatalf("pureLOC(func with lone closing brace): %v", err)
		}
		if got != 3 {
			t.Errorf("pureLOC(func with lone closing brace) = %d, want 3 (package, func header, brace)", got)
		}
	})
}

func TestSizeGuardDetectsOversizeFile(t *testing.T) {
	writtenDir := func(t *testing.T, n int) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "sized.go")
		if err := os.WriteFile(path, sizedSource(n), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return dir
	}

	t.Run("260 pure LOC is named as a violation", func(t *testing.T) {
		offenders, scanned, err := sizeViolations(writtenDir(t, 260))
		if err != nil {
			t.Fatalf("sizeViolations: %v", err)
		}
		if scanned != 1 {
			t.Errorf("scanned = %d, want 1", scanned)
		}
		if len(offenders) != 1 {
			t.Fatalf("offenders = %v, want exactly one naming sized.go", offenders)
		}
		if !strings.Contains(offenders[0], "sized.go") || !strings.Contains(offenders[0], "260") {
			t.Errorf("offender %q must name sized.go and its 260 pure LOC", offenders[0])
		}
	})

	t.Run("250 pure LOC is allowed", func(t *testing.T) {
		offenders, scanned, err := sizeViolations(writtenDir(t, 250))
		if err != nil {
			t.Fatalf("sizeViolations: %v", err)
		}
		if scanned != 1 {
			t.Errorf("scanned = %d, want 1", scanned)
		}
		if len(offenders) != 0 {
			t.Errorf("offenders = %v, want none at exactly %d pure LOC", offenders, maxPureLOC)
		}
	})
}

func TestSizeCeiling(t *testing.T) {
	root := repoRoot(t)
	offenders, scanned, err := sizeViolations(root)
	if err != nil {
		t.Fatalf("sizeViolations(%s): %v", root, err)
	}
	if scanned == 0 {
		t.Fatal("size guard scanned zero production files: the ceiling would be vacuous")
	}
	t.Logf("size guard: scanned %d production files, %d offending", scanned, len(offenders))
	for _, offender := range offenders {
		t.Errorf("production file exceeds %d pure LOC: %s", maxPureLOC, offender)
	}

	// The ceiling covers production code only: a guard test file must not be
	// counted as production, however large it is.
	rel := "internal/guards/normalization_guard_test.go"
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if isProductionFile(rel, src) {
		t.Errorf("isProductionFile(%q) = true, want false for a test file", rel)
	}
}
