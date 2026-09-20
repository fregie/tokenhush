// docs_guard_test.go asserts the D8 documentation contract structurally: the
// documentation tree is exactly the frozen set, the documented command set
// equals the CLI's real command set (parsed from the register() calls in
// internal/cli rather than kept in a second hand-maintained list), and
// docs/security.md records every invariant and every residual risk in the
// tables this guard parses.
//
// The synthetic half (TestDocsGuardCommandSet) is the always-running positive
// control for documentedCommands + commandSetViolations. The product half
// (TestDocsGuardProductTree) is complete as of W6.5: docs/ and internal/cli
// both exist, so it fails - rather than skips - when a doc is missing, an
// unexpected file appears under docs/ (including docs/README.md), a command is
// documented that the CLI does not register, a registered command is not
// documented, or a security register row is missing or misstated.
//
// "Structural" means: command registrations are read from the AST, the
// security registers are parsed as markdown tables and compared as sets
// against the frozen register below, each registered owner file must exist
// and declare the named test its row advertises. A grep for a name alone
// would satisfy none of these.
package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// d8Docs is the D8 documentation set: every one of these files must exist.
var d8Docs = []string{
	"README.md",
	"README.zh-CN.md",
	"docs/architecture.md",
	"docs/architecture.zh-CN.md",
	"docs/security.md",
	"docs/security.zh-CN.md",
	"docs/plugins.md",
	"docs/plugins.zh-CN.md",
}

// extraAllowedDocs are non-D8 files permitted under docs/.
//
// docs/AGENTS.md is the AI-agent knowledge base for the docs tree. It is
// agent metadata, not product documentation, so it has no .zh-CN.md twin:
// the bilingual rule below applies to the D8 set, not to this file.
var extraAllowedDocs = []string{
	"docs/AGENTS.md",
	"docs/PRO-MIGRATION.md",
	"docs/tool-setup.md",
	"docs/verify.md",
	"docs/deployment.md",
	"docs/generated/network-egress.md",
	"docs/PRO-MIGRATION.zh-CN.md",
	"docs/tool-setup.zh-CN.md",
	"docs/verify.zh-CN.md",
	"docs/deployment.zh-CN.md",
	"docs/generated/network-egress.zh-CN.md",
}

// realCLICommands is the CLI's frozen command set (D7). It is the expectation
// registeredCLICommands must reproduce from internal/cli's source, so an
// eighth command fails the guard even if the docs were updated to mention it.
var realCLICommands = []string{"run", "rules", "update", "status", "env", "version", "privacy"}

// docsInvariant is one row of the invariant register docs/security.md must
// carry: the invariant number, its exact name, its named test and the test
// file that owns it. File is checked against the repository; Name and Test are
// compared exactly against the parsed table.
type docsInvariant struct {
	Number int
	Name   string
	Test   string
	File   string
}

// d8Invariants is the frozen invariant register: eight rows, exact names and
// exact named tests.
var d8Invariants = []docsInvariant{
	{1, "Never backfill placeholders outbound", "TestInvariant1NeverBackfillOutbound", "pkg/redact/invariants_test.go"},
	{2, "No request/response plaintext on disk; metadata only", "TestInvariant2NoPlaintextOnDisk", "pkg/audit/invariants_test.go"},
	{3, "No root certificate, no MITM by default", "TestAbsenceNoCertificateInstallPath", "internal/guards/absence_guard_test.go"},
	{4, "Loopback-only bind, Host/Origin validation and the control bearer token", "TestInvariant4LoopbackOnly", "pkg/proxy/invariants_test.go"},
	{5, "Fail-safe on detection failure, not fail-open", "TestInvariant5FailSafe", "pkg/filter/invariants_test.go"},
	{6, "Exactly two switchable vendor-bound egress categories, command-scoped", "TestInvariant6NoVendorEgress", "pkg/proxy/invariants_test.go"},
	{7, "Content-Encoding fail-closed", "TestInvariant7EncodingFailClosed", "pkg/proxy/invariants_test.go"},
	{8, "SSE-aware bounded backfill (256 KiB)", "TestInvariant8BoundDerived", "pkg/redact/invariants_test.go"},
}

// docsResidualRisk is one row of the residual-risk register docs/security.md
// must carry: the risk id, its exact name, and fragments that must appear
// inside that row's own explanation cell, so the name cannot be present while
// the substance is gone.
type docsResidualRisk struct {
	ID      string
	Name    string
	Details []string
}

// d8ResidualRisks is the frozen residual-risk register: four rows, recorded
// honestly rather than described as absent.
var d8ResidualRisks = []docsResidualRisk{
	{"R1", "Encoded secrets are not caught", []string{"base64", "hex", "URL-encoded"}},
	{"R2", "A secret in a JSON object key is not caught", []string{"object key", "D10"}},
	{"R3", "A signed remote pack may weaken detection through its own allowlist", []string{"allowlist", "OD-3", "trust root"}},
	{"R4", "The OD-2 command-rule rejection is dormant and the v2 manifest bump is backward-incompatible", []string{"OD-2", "OD-4", "schema_version", "== 1"}},
}

// d8SecurityStatements are sentences docs/security.md must state, compared
// after backticks and case are removed. They pin the SSE limitation and the
// direction contract so a future edit cannot quietly drop them.
var d8SecurityStatements = []string{
	"a response-scoped block on a buffered sse response is a 502 before any byte is committed",
	"redact is request-path only",
	"rejected at compile time and again at registration",
}

var (
	docsBacktickRe   = regexp.MustCompile("`([^`\n]+)`")
	docsCommandRe    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	docsResidualIDRe = regexp.MustCompile(`^R[0-9]+$`)
)

// documentedCommands extracts every command named as `tokenhush <cmd>` or as a
// fenced-code line starting with "tokenhush <cmd>". Trailing words and flags
// are ignored. The result is distinct and sorted.
func documentedCommands(text string) []string {
	seen := map[string]bool{}
	record := func(token string) {
		fields := strings.Fields(token)
		if len(fields) < 2 || fields[0] != "tokenhush" {
			return
		}
		cmd := fields[1]
		if !docsCommandRe.MatchString(cmd) {
			return
		}
		seen[cmd] = true
	}
	for _, m := range docsBacktickRe.FindAllStringSubmatch(text, -1) {
		record(m[1])
	}
	inFence := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence && strings.HasPrefix(line, "tokenhush ") {
			record(line)
		}
	}
	out := make([]string, 0, len(seen))
	for cmd := range seen {
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
}

// commandSetViolations reports every mismatch between the documented command
// set and the CLI's real command set. The result is sorted and deduplicated.
func commandSetViolations(documented, real []string) []string {
	docSet := guardsStringSet(documented)
	realSet := guardsStringSet(real)
	var out []string
	if len(docSet) == 0 {
		out = append(out, "documented command set is empty")
	}
	for cmd := range docSet {
		if !realSet[cmd] {
			out = append(out, fmt.Sprintf("documented command %s does not exist in the CLI", cmd))
		}
	}
	for cmd := range realSet {
		if !docSet[cmd] {
			out = append(out, fmt.Sprintf("CLI command %s is not documented", cmd))
		}
	}
	sort.Strings(out)
	return guardsUniqueStrings(out)
}

// registeredCLICommands parses the production Go files of internal/cli and
// returns the sorted, distinct command names registered with
// register("<name>", ...). It is the AST ground truth the documented command
// set is compared against, so a command cannot be registered without being
// documented and a documented command cannot exist without a registration.
func registeredCLICommands(t *testing.T, cliDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(cliDir)
	if err != nil {
		t.Fatalf("read %s: %v", cliDir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(cliDir, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "register" || len(call.Args) != 2 {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil || !docsCommandRe.MatchString(name) {
				return true
			}
			names = append(names, name)
			return true
		})
	}
	sort.Strings(names)
	names = guardsUniqueStrings(names)
	if len(names) == 0 {
		t.Fatal("internal/cli registers no commands; the guard cannot compare a command set")
	}
	return names
}

// docsMarkdownRows splits every markdown table row in text into its cells,
// dropping the empty leading and trailing cells a piped row carries. Rows of
// any shape are returned; each caller keeps only the rows matching its shape.
func docsMarkdownRows(text string) [][]string {
	var rows [][]string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) > 0 && strings.TrimSpace(cells[0]) == "" {
			cells = cells[1:]
		}
		if len(cells) > 0 && strings.TrimSpace(cells[len(cells)-1]) == "" {
			cells = cells[:len(cells)-1]
		}
		trimmed := make([]string, len(cells))
		for i, cell := range cells {
			trimmed[i] = strings.TrimSpace(cell)
		}
		rows = append(rows, trimmed)
	}
	return rows
}

// docsStripCode removes inline-code backticks so prose comparisons are not
// defeated by formatting.
func docsStripCode(text string) string { return strings.ReplaceAll(text, "`", "") }

// docsInvariantViolations compares the invariant table in security.md with the
// frozen register: a row must be a four-cell table row whose first cell is the
// invariant number, and its name, test and owner file must match exactly.
func docsInvariantViolations(text string) []string {
	got := map[int]docsInvariant{}
	for _, cells := range docsMarkdownRows(text) {
		if len(cells) != 4 {
			continue
		}
		number, err := strconv.Atoi(cells[0])
		if err != nil || number < 1 || number > len(d8Invariants) {
			continue
		}
		got[number] = docsInvariant{Number: number, Name: cells[1], Test: docsStripCode(cells[2]), File: docsStripCode(cells[3])}
	}
	var out []string
	for _, want := range d8Invariants {
		actual, ok := got[want.Number]
		if !ok {
			out = append(out, fmt.Sprintf("security.md: invariant %d (%s) is missing from the register table", want.Number, want.Name))
			continue
		}
		if actual.Name != want.Name {
			out = append(out, fmt.Sprintf("security.md: invariant %d name = %q, want %q", want.Number, actual.Name, want.Name))
		}
		if actual.Test != want.Test {
			out = append(out, fmt.Sprintf("security.md: invariant %d named test = %q, want %q", want.Number, actual.Test, want.Test))
		}
		if actual.File != want.File {
			out = append(out, fmt.Sprintf("security.md: invariant %d owner file = %q, want %q", want.Number, actual.File, want.File))
		}
	}
	return out
}

// docsDeclaredTests parses the Go file at path and returns the set of its
// top-level function names. The invariant table is the audit's ground truth,
// so a named test that is not declared at its owner path is a violation.
func docsDeclaredTests(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	names := map[string]bool{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			names[fn.Name.Name] = true
		}
	}
	return names, nil
}

// docsResidualRiskViolations compares the residual-risk table in security.md
// with the frozen register. Name must match exactly, and every registered
// detail fragment must appear inside that risk's own explanation cell.
func docsResidualRiskViolations(text string) []string {
	got := map[string][]string{}
	for _, cells := range docsMarkdownRows(text) {
		if len(cells) != 4 || !docsResidualIDRe.MatchString(cells[0]) {
			continue
		}
		got[cells[0]] = cells
	}
	var out []string
	for _, want := range d8ResidualRisks {
		cells, ok := got[want.ID]
		if !ok {
			out = append(out, fmt.Sprintf("security.md: residual risk %s (%s) is missing from the register table", want.ID, want.Name))
			continue
		}
		if cells[1] != want.Name {
			out = append(out, fmt.Sprintf("security.md: residual risk %s name = %q, want %q", want.ID, cells[1], want.Name))
		}
		explanation := strings.ToLower(docsStripCode(cells[2]))
		for _, fragment := range want.Details {
			if !strings.Contains(explanation, strings.ToLower(fragment)) {
				out = append(out, fmt.Sprintf("security.md: residual risk %s explanation is missing %q", want.ID, fragment))
			}
		}
	}
	return out
}

// docsSecurityStatementViolations reports every required statement that
// security.md does not carry (compared after stripping backticks and case, and
// after collapsing the prose line wrapping so a statement can span lines).
func docsSecurityStatementViolations(text string) []string {
	normalized := strings.ToLower(docsStripCode(text))
	normalized = strings.Join(strings.Fields(normalized), " ")
	var out []string
	for _, statement := range d8SecurityStatements {
		if !strings.Contains(normalized, statement) {
			out = append(out, fmt.Sprintf("security.md: does not state %q", statement))
		}
	}
	return out
}

// guardsStringSet builds a set from non-empty strings.
func guardsStringSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		if item != "" {
			set[item] = true
		}
	}
	return set
}

// guardsUniqueStrings removes duplicates, preserving first-seen order.
func guardsUniqueStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// guardsPathIsDir reports whether path exists and is a directory.
func guardsPathIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// guardsPathExists reports whether path exists at all.
func guardsPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestDocsGuardCommandSet is the always-running positive control: it proves the
// extractor finds commands in both documented shapes and that violations name
// both a documented-but-not-real command and every missing real command.
func TestDocsGuardCommandSet(t *testing.T) {
	partial := "# Docs\n\nStart with `tokenhush run --deep`.\n\n```sh\ntokenhush doctor\n```\n\nThen `tokenhush rules` lists the rules.\n"
	got := documentedCommands(partial)
	want := []string{"doctor", "rules", "run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("documentedCommands = %v, want %v", got, want)
	}

	violations := commandSetViolations(got, realCLICommands)
	if !guardsContainsString(violations, "documented command doctor does not exist in the CLI") {
		t.Errorf("violations = %v, want documented-but-not-real doctor", violations)
	}
	for _, missing := range []string{"status", "env", "version", "privacy", "update"} {
		wanted := "CLI command " + missing + " is not documented"
		if !guardsContainsString(violations, wanted) {
			t.Errorf("violations = %v, want %q", violations, wanted)
		}
	}
	for _, bogus := range []string{
		"documented command run does not exist in the CLI",
		"documented command rules does not exist in the CLI",
	} {
		if guardsContainsString(violations, bogus) {
			t.Errorf("violations = %v, unexpected %q", violations, bogus)
		}
	}

	if v := commandSetViolations(nil, realCLICommands); !guardsContainsString(v, "documented command set is empty") {
		t.Errorf("violations = %v, want emptiness violation", v)
	}

	var matching strings.Builder
	matching.WriteString("# Commands\n\n")
	for _, cmd := range realCLICommands {
		fmt.Fprintf(&matching, "`tokenhush %s`\n\n", cmd)
	}
	if v := commandSetViolations(documentedCommands(matching.String()), realCLICommands); len(v) != 0 {
		t.Errorf("matching doc produced violations: %v", v)
	}
}

// guardsContainsString reports whether items contains want.
func guardsContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// TestDocsGuardProductTree checks the real documentation tree: every D8 path
// exists, docs/ holds exactly the D8 subset plus docs/PRO-MIGRATION.md, the
// documented command set equals the CLI's real (parsed) command set, and
// docs/security.md records every invariant and every residual risk.
func TestDocsGuardProductTree(t *testing.T) {
	root := repoRoot(t)
	docsDir := filepath.Join(root, "docs")
	cliDir := filepath.Join(root, "internal", "cli")
	if !guardsPathIsDir(docsDir) {
		t.Fatalf("docs/ does not exist: the D8 documentation tree is required")
	}
	if !guardsPathIsDir(cliDir) {
		t.Fatalf("internal/cli does not exist: cannot derive the real command set")
	}

	expected := map[string]bool{}
	for _, rel := range d8Docs {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("doc %s is missing: %v", rel, err)
		}
		if strings.HasPrefix(rel, "docs/") {
			expected[strings.TrimPrefix(rel, "docs/")] = true
		}
	}
	for _, rel := range extraAllowedDocs {
		expected[strings.TrimPrefix(rel, "docs/")] = true
	}

	actual := map[string]bool{}
	walkErr := filepath.WalkDir(docsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(docsDir, path)
		if relErr != nil {
			return relErr
		}
		actual[filepath.ToSlash(rel)] = true
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk docs/: %v", walkErr)
	}
	for file := range actual {
		if !expected[file] {
			t.Errorf("unexpected file under docs/: %s", file)
		}
	}
	for file := range expected {
		if !actual[file] {
			t.Errorf("required file missing under docs/: %s", file)
		}
	}

	registered := registeredCLICommands(t, cliDir)
	wantRegistered := slices.Clone(realCLICommands)
	slices.Sort(wantRegistered)
	if !slices.Equal(registered, wantRegistered) {
		t.Errorf("internal/cli registers %v, want the frozen seven %v", registered, wantRegistered)
	}

	var documented []string
	for _, rel := range d8Docs {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		documented = append(documented, documentedCommands(string(data))...)
	}
	for _, violation := range commandSetViolations(documented, registered) {
		t.Error(violation)
	}

	for _, invariant := range d8Invariants {
		owner := filepath.Join(root, filepath.FromSlash(invariant.File))
		if _, err := os.Stat(owner); err != nil {
			t.Errorf("invariant %d owner file %s is missing: %v", invariant.Number, invariant.File, err)
			continue
		}
		declared, err := docsDeclaredTests(owner)
		if err != nil {
			t.Errorf("invariant %d owner file %s: %v", invariant.Number, invariant.File, err)
			continue
		}
		if !declared[invariant.Test] {
			t.Errorf("invariant %d named test %s is not declared in %s", invariant.Number, invariant.Test, invariant.File)
		}
	}

	security, err := os.ReadFile(filepath.Join(docsDir, "security.md"))
	if err != nil {
		t.Fatalf("read docs/security.md: %v", err)
	}
	text := string(security)
	for _, violation := range docsInvariantViolations(text) {
		t.Error(violation)
	}
	for _, violation := range docsResidualRiskViolations(text) {
		t.Error(violation)
	}
	for _, violation := range docsSecurityStatementViolations(text) {
		t.Error(violation)
	}
}

// TestToolSetupDocumentsResponseLimits pins the response-limit configuration
// keys in the tool-setup configuration reference: the whole response is
// buffered, so the total buffer cap and the read deadline are documented with
// their defaults beside the existing request-side keys.
func TestToolSetupDocumentsResponseLimits(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "docs", "tool-setup.md"))
	if err != nil {
		t.Fatalf("read docs/tool-setup.md: %v", err)
	}
	normalized := strings.ToLower(docsStripCode(string(data)))
	normalized = strings.Join(strings.Fields(normalized), " ")
	for _, want := range []string{"response_buffer_bytes", "response_timeout", "32 mib", "5m"} {
		if !strings.Contains(normalized, want) {
			t.Errorf("docs/tool-setup.md does not document %q", want)
		}
	}
}

// TestReadmeDropsStreamingClaim pins the README response contract: README.md
// states the whole response is buffered before any byte is committed, and
// carries no claim that a block takes effect from the first whole event or that
// emitted deltas can be recalled.
func TestReadmeDropsStreamingClaim(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	normalized := strings.ToLower(docsStripCode(string(data)))
	normalized = strings.Join(strings.Fields(normalized), " ")
	for _, claim := range []string{
		"first whole event",
		"cannot recall deltas already emitted",
	} {
		if strings.Contains(normalized, claim) {
			t.Errorf("README.md still claims %q; the response is buffered whole before any byte is committed", claim)
		}
	}
}
