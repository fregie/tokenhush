// Size guard: the 250-pure-LOC ceiling keeps every production file small
// enough to hold in one head. A line counts only when it carries code: blank
// lines, comment-only lines, the package clause and lines made up purely of
// structural punctuation never count. Test files, testdata, generated files,
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

// structuralTokens are punctuation tokens that only open, close or separate a
// construct. A line built purely from them is the tail (or head) of a
// construct that is already counted where it carries content, so it is not a
// line of code a reader has to hold in their head.
var structuralTokens = map[token.Token]bool{
	token.LPAREN:    true,
	token.RPAREN:    true,
	token.LBRACE:    true,
	token.RBRACE:    true,
	token.LBRACK:    true,
	token.RBRACK:    true,
	token.COMMA:     true,
	token.SEMICOLON: true,
}

// pureLOC counts the lines of src that carry code. A line counts when it
// contains at least one token that is not a comment, not an automatically
// inserted semicolon, not part of the package clause, and not structural
// punctuation. Blank lines and comment-only lines therefore count zero.
func pureLOC(src []byte) (int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "pureloc.go", src, parser.ParseComments)
	if err != nil {
		return 0, fmt.Errorf("pure LOC: parse: %w", err)
	}
	pkgStart, pkgEnd := file.Package, file.Name.End()

	scanSet := token.NewFileSet()
	tf := scanSet.AddFile("pureloc.go", scanSet.Base(), len(src))
	var s scanner.Scanner
	s.Init(tf, src, nil, scanner.ScanComments)
	lineTokens := map[int][]token.Token{}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT || (tok == token.SEMICOLON && lit == "\n") {
			continue
		}
		if pos >= pkgStart && pos <= pkgEnd {
			continue // the package clause is boilerplate, not code
		}
		line := tf.Line(pos)
		lineTokens[line] = append(lineTokens[line], tok)
	}

	count := 0
	for _, toks := range lineTokens {
		if carriesCode(toks) {
			count++
		}
	}
	return count, nil
}

// carriesCode reports whether a line's tokens go beyond structural punctuation.
func carriesCode(toks []token.Token) bool {
	for _, tok := range toks {
		if !structuralTokens[tok] {
			return true
		}
	}
	return false
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

// sizedSource returns a parseable source file with exactly n pure LOC: one
// package clause and n single-line variable declarations, separated by blank
// lines. The package clause and the blanks never count, so the declarations
// alone carry the n.
func sizedSource(n int) []byte {
	lines := make([]string, 0, 2*n+2)
	lines = append(lines, "package probe", "")
	for i := 0; i < n; i++ {
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
		lines := []string{"package probe", ""}
		for i := 0; i < 260; i++ {
			lines = append(lines, fmt.Sprintf("var v%d = %d", i, i), "", fmt.Sprintf("// comment %d", i), "")
		}
		got, err := pureLOC([]byte(strings.Join(lines, "\n") + "\n"))
		if err != nil {
			t.Fatalf("pureLOC(260 code lines with blanks and comments): %v", err)
		}
		if got != 260 {
			t.Errorf("pureLOC(260 code lines with blanks and comments) = %d, want 260", got)
		}
	})

	t.Run("comments and blanks alone count zero", func(t *testing.T) {
		src := []byte("package probe\n\n// nothing to count here\n\n// and nothing here\n")
		got, err := pureLOC(src)
		if err != nil {
			t.Fatalf("pureLOC(comment-only file): %v", err)
		}
		if got != 0 {
			t.Errorf("pureLOC(comment-only file) = %d, want 0", got)
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
