package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// optionsContractPath is the committed golden of the frozen ADR-0012 assembly
// contract. TestOptionsContractDoc reflects over the exported struct fields and
// fails when one is added, removed, renamed or retyped.
var optionsContractPath = filepath.Join("testdata", "options_contract.txt")

// contractTypes are the structs the ADR freezes.
func contractTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(Deps{}),
		reflect.TypeOf(Options{}),
		reflect.TypeOf(BuildOptions{}),
		reflect.TypeOf(RequestStats{}),
	}
}

// describeContract renders one "Struct Field Type" line per exported field,
// sorted so the golden is independent of declaration order.
func describeContract(types []reflect.Type) []string {
	var lines []string
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue // unexported
			}
			lines = append(lines, typ.Name()+" "+field.Name+" "+field.Type.String())
		}
	}
	sort.Strings(lines)
	return lines
}

// readContractGolden loads the golden and strips its comment/blank lines.
func readContractGolden(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(optionsContractPath)
	if err != nil {
		t.Fatalf("read contract golden %s: %v", optionsContractPath, err)
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// TestOptionsContractDoc pins the exported fields of the four frozen structs
// against the ADR-0012 golden. Removing one golden field, adding a struct
// field, renaming one or changing a type all change the reflected "Struct
// Field Type" line set and fail the comparison.
func TestOptionsContractDoc(t *testing.T) {
	got := describeContract(contractTypes())
	want := readContractGolden(t)

	gotText := strings.Join(got, "\n")
	wantText := strings.Join(want, "\n")
	if gotText != wantText {
		t.Errorf("pkg/gateway assembly contract drifted from %s\n--- golden ---\n%s\n--- reflected ---\n%s",
			optionsContractPath, wantText, gotText)
	}
}
