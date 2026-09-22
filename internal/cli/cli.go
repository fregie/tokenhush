// Package cli assembles the tokenhush command line: it is the only place that
// wires pkg/proxy, pkg/filter, pkg/redact and pkg/supply into a running
// product. cli.go holds the dispatcher and the content-policy glue that turns
// rule decisions into proxy verdicts; the run command and the HTTP surface live
// in run.go, and the client-bound response writer in response_writer.go.
package cli

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/filter"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/supply"
)

// Frozen exit codes: scripts observe them, so they never change. A success is
// 0, a failed check or operation is 1, and a usage error (an unknown command
// or tool, a bad flag value) is 2.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// logLevels is the closed set of accepted log levels, mirroring the config
// schema.
var logLevels = []string{"debug", "info", "warn", "error"}

// command is one CLI verb: it receives its own arguments and the two streams
// and returns the process exit code.
type command func(args []string, stdout, stderr io.Writer) int

// commands is the command registry. Every command file registers itself from
// its init, so adding a command never edits the dispatcher.
var commands = map[string]command{}

// register installs one command under its verb.
func register(name string, run command) { commands[name] = run }

// Main dispatches the process arguments and returns the exit code.
func Main(args []string) int { return dispatch(args, os.Stdout, os.Stderr) }

// dispatch runs one command. An unknown command, or no command at all, is a
// usage error listing the registered commands in sorted order, so the help
// text can never advertise a command that does not exist.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		if run, ok := commands[args[0]]; ok {
			return run(args[1:], stdout, stderr)
		}
		fmt.Fprintf(stderr, "tokenhush: unknown command %q\n", args[0])
	}
	fmt.Fprintf(stderr, "usage: tokenhush <%s>\n", strings.Join(slices.Sorted(maps.Keys(commands)), "|"))
	return exitUsage
}

// errBlocked is the transform error for a request-scoped Block. It is never
// client-visible: the data plane answers 403 before the body reaches the
// forwarder, so this only fires if a transform is invoked outside the plane.
var errBlocked = fmt.Errorf("cli: request blocked by content policy")

// EvaluateRequest implements proxy.RequestEvaluator: the request-phase policy
// verdict. A rule failure is a labelled detector failure, so the data plane
// refuses it with plugin_failure; a Block names the rule ids.
func (g *gateway) EvaluateRequest(_ context.Context, leaves []protocol.Leaf) (proxy.RequestDecision, error) {
	decision, err := g.policy.Decide(leaves, filter.ScopeRequest)
	if err != nil {
		return proxy.RequestDecision{}, err
	}
	if decision.Refusal != nil {
		return proxy.RequestDecision{}, &proxy.DetectorFailure{RuleID: decision.Refusal.RuleID, Reason: proxy.FailureReason(decision.Refusal.Reason)}
	}
	if decision.Action == filter.ActionBlock {
		return proxy.RequestDecision{Action: proxy.RequestBlock, RuleIDs: ruleIDs(decision.Findings)}, nil
	}
	return proxy.RequestDecision{Action: proxy.RequestAllow}, nil
}

// EvaluateResponse implements proxy.Evaluator: the response-phase policy
// verdict. A body that cannot be walked is an error, which the response paths
// treat as the documented walk skip; a rule failure fails closed as a block,
// and the direction contract admits exactly allow, warn and block here.
func (g *gateway) EvaluateResponse(_ context.Context, body []byte) (proxy.ResponseDecision, error) {
	leaves, err := protocol.Walk(body)
	if err != nil {
		return proxy.ResponseDecision{}, err
	}
	decision, err := g.policy.Decide(leaves, filter.ScopeResponse)
	if err != nil {
		return proxy.ResponseDecision{}, err
	}
	if decision.Refusal != nil {
		return proxy.ResponseDecision{Action: proxy.ResponseBlock, RuleIDs: []string{decision.Refusal.RuleID}}, nil
	}
	if decision.Action == filter.ActionAllow {
		return proxy.ResponseDecision{Action: proxy.ResponseAllow}, nil
	}
	ids := ruleIDs(decision.Findings)
	action := proxy.ResponseWarn
	if decision.Action != filter.ActionWarn {
		action = proxy.ResponseBlock
	}
	return proxy.ResponseDecision{Action: action, RuleIDs: ids}, nil
}

// ruleIDs extracts the rule ids of a decision's backing findings.
func ruleIDs(findings []filter.AttributedFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

// Masking policy of the redaction log. Every class is bounded and can never
// equal the secret it hides: an opaque credential type reveals a bounded prefix
// and suffix; a private-key block names only its PEM kind, drawn from the
// closed pemKinds allowlist, never the captured header text; an email address
// reveals only its domain with the local part hidden; every other type reveals
// nothing. A masked form equal to the value, including a literal "****",
// becomes the distinct fallback "[redacted]".
var maskEdgeTypes = map[string]bool{"api_key": true, "high_entropy": true}

// pemKinds is the closed allowlist of PEM private-key header literals the log
// may name. The PEM detector matches any [A-Z0-9 ]* run before "PRIVATE KEY",
// so the captured run can be secret or attacker-controlled text; the log emits
// a literal from this list and never the captured run.
var pemKinds = []string{
	"PRIVATE KEY",
	"RSA PRIVATE KEY",
	"EC PRIVATE KEY",
	"DSA PRIVATE KEY",
	"OPENSSH PRIVATE KEY",
	"ENCRYPTED PRIVATE KEY",
	"PGP PRIVATE KEY BLOCK",
}

// maxMaskDomainBytes caps the revealed email domain so a pathological value
// cannot be echoed whole; a longer domain falls back to the no-reveal form.
const maxMaskDomainBytes = 64

// maskSecret returns the masked, human-readable form of one redacted value for
// the frozen redaction-log format. It works on runes, so a multi-byte value is
// never split mid-character, and it never returns the value itself.
func maskSecret(value, kind string) string {
	masked := "****"
	switch runes := []rune(value); {
	case maskEdgeTypes[kind] && len(runes) >= 16 && len(runes)-6 >= 8:
		masked = string(runes[:4]) + "…" + string(runes[len(runes)-2:])
	case kind == filter.CategoryPrivateKey:
		if pem := pemKind(value); pem != "" {
			masked = pem
		}
	case kind == filter.CategoryEmail:
		if domain := emailDomain(value); domain != "" {
			masked = "****@" + domain
		}
	}
	if masked == value {
		return "[redacted]"
	}
	return masked
}

// pemKind returns value's PEM private-key header literal when it is one of the
// pemKinds allowlist, and empty otherwise, so no captured header text is ever
// echoed.
func pemKind(value string) string {
	for _, kind := range pemKinds {
		if strings.HasPrefix(value, "-----BEGIN "+kind+"-----") {
			return kind
		}
	}
	return ""
}

// emailDomain returns the domain of an '@'-delimited pair with a non-empty
// local and domain part and no second '@', or empty otherwise. A domain past
// maxMaskDomainBytes yields empty so the caller falls back to the no-reveal
// form.
func emailDomain(value string) string {
	at := strings.IndexByte(value, '@')
	if at <= 0 || at == len(value)-1 || strings.IndexByte(value[at+1:], '@') >= 0 {
		return ""
	}
	if domain := value[at+1:]; len(domain) <= maxMaskDomainBytes {
		return domain
	}
	return ""
}

// Warn implements proxy.WarningWriter: the proxy's metadata-only response
// warning lines go to stderr and nowhere else.
func (g *gateway) Warn(line string) {
	if g.stderr != nil {
		fmt.Fprintln(g.stderr, line)
	}
}

// selectBuiltins maps the operator's detector switches onto the frozen
// built-in rule table, preserving the table's order. Every selected rule scans
// with budget, so the detector budget is aligned with the configured scan
// budget.
func selectBuiltins(detectors config.Detectors, budget int) []filter.Rule {
	enabled := map[string]bool{
		filter.DetectorPrefix: detectors.Prefix, filter.DetectorEmail: detectors.Email, filter.DetectorLuhn: detectors.Luhn,
		filter.DetectorJWT: detectors.JWT, filter.DetectorPrivateKey: detectors.PEM, filter.DetectorHighEntropy: detectors.Entropy,
	}
	rules := make([]filter.Rule, 0, len(enabled))
	for _, rule := range filter.BuiltinDetectorsBudget(budget) {
		if enabled[rule.ID()] {
			rules = append(rules, rule)
		}
	}
	return rules
}

// scanBudget converts the configured scan budget to the int the filter
// package's per-primitive budget uses. A config value that is non-positive or
// does not fit an int falls back to the documented default rather than
// wrapping into a budget that scans nothing.
func scanBudget(cfg config.Config) int {
	if cfg.ScanBudgetBytes <= 0 || int64(int(cfg.ScanBudgetBytes)) != cfg.ScanBudgetBytes {
		return filter.PrimitiveByteBudgetBytes
	}
	return int(cfg.ScanBudgetBytes)
}

// loadCachedPack activates the verified pack the rules cache holds, compiling
// every primitive-typed pack rule with budget so the pack and the built-ins
// scan with the same per-primitive budget. A missing cache is normal (the
// built-ins stay active); a corrupt one is reported and the built-ins stay,
// because a cache read failure must never block startup. Every warning the
// activation carries (for example the OD-2 command-rule warning) is written to
// stderr, so it is never silently dropped.
func loadCachedPack(registry *filter.Registry, dataDir string, budget int, stderr io.Writer, verifier supply.Verifier) error {
	sync, err := supply.NewRulesSync(supply.RulesSyncConfig{
		DataDir: dataDir, Verifier: verifier,
		Fetcher: supply.NewBoundedHTTPFetcher(30*time.Second, supply.MaxRulesDocBytes),
		Budget:  budget,
	})
	if err != nil {
		return err
	}
	if err := sync.Startup(); err != nil {
		fmt.Fprintf(stderr, "tokenhush: rules cache: %v (using the built-in detectors)\n", err)
		return nil
	}
	state := sync.Active()
	for _, warning := range state.Warnings {
		fmt.Fprintf(stderr, "tokenhush: %s\n", warning)
	}
	if state.Pack == nil {
		return nil
	}
	return registry.RegisterCompiled(state.Pack)
}
