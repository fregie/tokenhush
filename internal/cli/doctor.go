package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/gateway"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// Doctor check statuses, worst-last. A report is OK when no check failed; any
// failed check exits the process non-zero. `--json` consumers and tests match
// on these exact strings.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
)

// Stable check names. `tool:<name>` carries one check per client tool.
const (
	doctorCheckConfig    = "config"
	doctorCheckConfigDir = "config-dir"
	doctorCheckDataDir   = "data-dir"
	doctorCheckSecrets   = "secret-store"
	doctorCheckLoopback  = "loopback"
	doctorCheckPort      = "port"
	doctorCheckProxyEnv  = "proxy-env"
	doctorToolPrefix     = "tool:"
)

// doctorConfigFileName mirrors pkg/platform's unexported name for the default
// configuration file; it is only used to describe the effective config source.
const doctorConfigFileName = "tokenhush.yaml"

// DoctorCheck is one named diagnostic result in a DoctorReport.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok | warn | fail
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// DoctorReport is the machine-readable document `tokenhush doctor --json`
// prints. Exit mirrors the process exit code and Status is the worst check
// status (ok -> warn -> fail); the per-check statuses stay authoritative.
type DoctorReport struct {
	OK     bool          `json:"ok"`
	Status string        `json:"status"`
	Exit   int           `json:"exit"`
	OS     string        `json:"os"`
	Arch   string        `json:"arch"`
	Shell  string        `json:"shell"`
	Port   int           `json:"port"`
	Checks []DoctorCheck `json:"checks"`
}

// doctorDeps carries every injectable seam of the doctor command. The zero
// value is unusable; defaultDoctorDeps wires the production platform, listener
// and environment probes.
type doctorDeps struct {
	stdout, stderr io.Writer
	configPath     string
	portOverride   int
	json           bool

	configDir  func() (string, error)
	dataDir    func() (string, error)
	loadConfig func(string) (*config.Config, error)
	openStore  func() (platform.SecretStore, error)
	listen     func(host string, port int) (io.Closer, error)
	shellMode  func() platform.ShellMode
	probeDir   func(string) error

	getenv      func(string) string
	lookPath    func(string) (string, error)
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	userHomeDir func() (string, error)
}

// defaultDoctorDeps is the production seam wiring. loadConfig reuses env.go's
// resolution unchanged: explicit path wins, otherwise platform default.
func defaultDoctorDeps(stdout, stderr io.Writer) doctorDeps {
	return doctorDeps{
		stdout:      stdout,
		stderr:      stderr,
		configDir:   platform.ConfigDir,
		dataDir:     platform.DataDir,
		loadConfig:  envLoadConfig,
		openStore:   platform.OpenSecretStore,
		shellMode:   platform.ShellSnippetMode,
		probeDir:    probeDirWritable,
		getenv:      os.Getenv,
		lookPath:    exec.LookPath,
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		userHomeDir: os.UserHomeDir,
		listen: func(host string, port int) (io.Closer, error) {
			ls, err := proxy.Listen(host, port)
			if err != nil {
				return nil, err
			}
			return ls, nil
		},
	}
}

// probeDirWritable creates dir if needed (repair) and proves it is writable
// with a short-lived probe file that is always removed. The probe name is not
// secret-bearing: it contains no configuration or key material.
func probeDirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tokenhush-doctor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.WriteString("probe")
	cerr := f.Close()
	rerr := os.Remove(name)
	return errors.Join(werr, cerr, rerr)
}

// doctorCommand is the CLI entry for `tokenhush doctor` (docs/12 §7): it
// reports port availability on both loopback families, config/data directory
// writability, the effective SecretStore backend (failing loudly on the
// plaintext fallback) and a best-effort base-URL hint per installed tool.
//
// Exit codes: 0 when no check failed, 1 when any critical check failed, 2 on a
// malformed invocation. The plaintext fallback, an unwritable directory, a
// missing secret backend, an invalid config and a busy port without a matching
// tokenhush session are critical; everything else is a warning.
func doctorCommand(args []string, stdout, stderr io.Writer) int {
	return doctorCommandWith(args, stdout, stderr, nil)
}

// doctorCommandWith carries the test seam of doctorCommand: inject may replace
// any doctorDeps field before the run. Explicit flags always win over injected
// fields.
func doctorCommandWith(args []string, stdout, stderr io.Writer, inject func(*doctorDeps)) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		configPath string
		port       int
		jsonOut    bool
	)
	fs.StringVar(&configPath, "config", "", "path to tokenhush.yaml (default: platform config dir)")
	fs.IntVar(&port, "port", 0, "override listen port (1..65535)")
	fs.BoolVar(&jsonOut, "json", false, "print a machine-readable JSON report")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tokenhush: doctor: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprintln(stderr, "usage: tokenhush doctor [--json] [--config PATH] [--port N]")
		return ExitUsage
	}
	if port != 0 && (port < 1 || port > 65535) {
		fmt.Fprintln(stderr, "tokenhush: doctor: --port must be in 1..65535")
		return ExitUsage
	}

	deps := defaultDoctorDeps(stdout, stderr)
	if inject != nil {
		inject(&deps)
	}
	if configPath != "" {
		deps.configPath = configPath
	}
	if port != 0 {
		deps.portOverride = port
	}
	deps.json = deps.json || jsonOut
	return runDoctor(deps)
}

// runDoctor collects the checks and renders the report. It never calls
// os.Exit: the returned int is the process exit code.
func runDoctor(deps doctorDeps) int {
	if deps.stdout == nil {
		deps.stdout = io.Discard
	}
	if deps.stderr == nil {
		deps.stderr = io.Discard
	}
	report := DoctorReport{
		Status: doctorOK,
		Exit:   ExitOK,
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		Shell:  string(deps.shellMode()),
	}

	cfg, configCheck := doctorConfig(deps)
	report.Checks = append(report.Checks, configCheck, doctorSecretStore(deps))
	report.Checks = append(report.Checks, doctorDirs(deps)...)
	if cfg != nil {
		port := int(cfg.Listen.Port)
		if deps.portOverride != 0 {
			port = deps.portOverride
		}
		report.Port = port
		report.Checks = append(report.Checks, doctorListeners(deps, cfg.Listen.Host, port)...)
		report.Checks = append(report.Checks, doctorTools(deps, port)...)
		report.Checks = append(report.Checks, doctorProxyEnv(deps))
	}

	failures, warnings := 0, 0
	for _, c := range report.Checks {
		switch c.Status {
		case doctorFail:
			failures++
		case doctorWarn:
			warnings++
		}
	}
	report.OK = failures == 0
	if !report.OK {
		report.Status, report.Exit = doctorFail, ExitFailure
	} else if warnings > 0 {
		report.Status = doctorWarn
	}

	if deps.json {
		if err := writeDoctorJSON(deps.stdout, report); err != nil {
			fmt.Fprintf(deps.stderr, "tokenhush: doctor: %v\n", err)
			return ExitFailure
		}
	} else {
		renderDoctorHuman(deps.stdout, report, failures, warnings)
	}
	return report.Exit
}

// doctorConfig loads the effective configuration and describes its source. An
// unloadable config is critical: `tokenhush run` would refuse the same file.
func doctorConfig(deps doctorDeps) (*config.Config, DoctorCheck) {
	cfg, err := deps.loadConfig(deps.configPath)
	if err != nil {
		return nil, DoctorCheck{
			Name:    doctorCheckConfig,
			Status:  doctorFail,
			Message: fmt.Sprintf("cannot load configuration: %v", err),
			Fix:     "fix the file above or rerun with --config PATH",
		}
	}

	var source string
	if deps.configPath != "" {
		source = "file " + deps.configPath
	} else if dir, derr := deps.configDir(); derr == nil {
		path := filepath.Join(dir, doctorConfigFileName)
		if _, rerr := deps.readFile(path); rerr == nil {
			source = "file " + path
		} else {
			source = "defaults (no " + path + ")"
		}
	} else {
		source = "defaults"
	}
	return cfg, DoctorCheck{
		Name:    doctorCheckConfig,
		Status:  doctorOK,
		Message: fmt.Sprintf("%s; listen %s:%d", source, cfg.Listen.Host, cfg.Listen.Port),
	}
}

// doctorDirs reports config and data directory writability, creating both
// (repair) via probeDir. Resolution and write failures are critical.
func doctorDirs(deps doctorDeps) []DoctorCheck {
	out := make([]DoctorCheck, 0, 2)
	for _, d := range []struct {
		name string
		dir  func() (string, error)
	}{
		{doctorCheckConfigDir, deps.configDir},
		{doctorCheckDataDir, deps.dataDir},
	} {
		check := DoctorCheck{Name: d.name}
		dir, err := d.dir()
		switch {
		case err != nil:
			check.Status = doctorFail
			check.Message = fmt.Sprintf("cannot resolve: %v", err)
			check.Fix = "set TOKENHUSH_HOME to a writable directory"
		default:
			if perr := deps.probeDir(dir); perr != nil {
				check.Status = doctorFail
				check.Message = fmt.Sprintf("%s is not writable: %v", dir, perr)
				check.Fix = "make the directory writable or point TOKENHUSH_HOME at one that is"
				break
			}
			check.Status = doctorOK
			check.Message = dir + " (writable)"
			if deps.getenv("TOKENHUSH_HOME") != "" {
				check.Message += "; TOKENHUSH_HOME override"
			}
		}
		out = append(out, check)
	}
	return out
}

// doctorSecretStore reports the backend the fallback chain actually selected.
// The plaintext layer is the one honest-degradation signal that must never be
// silent (docs/security.md): it fails the check and embeds the stable warning
// marker verbatim.
func doctorSecretStore(deps doctorDeps) DoctorCheck {
	store, err := deps.openStore()
	if err != nil {
		return DoctorCheck{
			Name:    doctorCheckSecrets,
			Status:  doctorFail,
			Message: fmt.Sprintf("no usable secret store: %v", err),
			Fix:     "enable an OS keyring or make the data directory writable",
		}
	}
	backend := store.Backend()
	if backend == platform.BackendFilePlaintext {
		return DoctorCheck{
			Name:    doctorCheckSecrets,
			Status:  doctorFail,
			Message: fmt.Sprintf("backend %s: %s", backend, platform.PlaintextWarningMarker),
			Fix:     "enable an OS keyring (Keychain / Credential Manager / gnome-keyring or KWallet)",
		}
	}
	msg := "backend " + backend
	if backend != platform.BackendKeyring {
		msg += " (degraded fallback; OS keyring unavailable)"
	}
	return DoctorCheck{Name: doctorCheckSecrets, Status: doctorOK, Message: msg}
}

// doctorListeners probes the loopback stack and the configured port. The
// ephemeral bind proves both families (127.0.0.1 and ::1) can be bound at all,
// mirroring how `run` binds them; the configured-port bind classifies a busy
// port as expected when run.json names the same port.
func doctorListeners(deps doctorDeps, host string, port int) []DoctorCheck {
	checks := make([]DoctorCheck, 0, 2)
	if err := doctorProbeListen(deps, host, 0); err != nil {
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckLoopback,
			Status:  doctorFail,
			Message: fmt.Sprintf("cannot bind both loopback families: %v", err),
			Fix:     "enable the IPv6 loopback interface (::1) and rerun",
		})
	} else {
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckLoopback,
			Status:  doctorOK,
			Message: "127.0.0.1 and [::1] bindable",
		})
	}

	switch err := doctorProbeListen(deps, host, port); {
	case err == nil:
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckPort,
			Status:  doctorOK,
			Message: fmt.Sprintf("127.0.0.1:%d and [::1]:%d available", port, port),
		})
	case errors.Is(err, proxy.ErrAddrInUse) && doctorSessionOnPort(deps, port):
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckPort,
			Status:  doctorOK,
			Message: fmt.Sprintf("port %d is held by the tokenhush session in %s", port, gateway.RunStateFileName),
		})
	case errors.Is(err, proxy.ErrAddrInUse):
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckPort,
			Status:  doctorFail,
			Message: fmt.Sprintf("port %d is already in use and no tokenhush session claims it", port),
			Fix:     fmt.Sprintf("stop the process holding port %d or run with --port N", port),
		})
	default:
		checks = append(checks, DoctorCheck{
			Name:    doctorCheckPort,
			Status:  doctorFail,
			Message: fmt.Sprintf("cannot bind port %d: %v", port, err),
			Fix:     "check firewall or sandbox permissions for loopback TCP",
		})
	}
	return checks
}

// doctorProbeListen binds and immediately releases host:port through the
// injected listener seam. A successful bind reports both families because
// proxy.Listen is dual-stack by construction.
func doctorProbeListen(deps doctorDeps, host string, port int) error {
	closer, err := deps.listen(host, port)
	if err != nil {
		return err
	}
	_ = closer.Close()
	return nil
}

// doctorSessionOnPort reports whether <dataDir>/run.json advertises port. The
// check is metadata-only; a stale run.json can only turn a hard port failure
// into a "session holds it" note, never the reverse.
func doctorSessionOnPort(deps doctorDeps, port int) bool {
	dir, err := deps.dataDir()
	if err != nil {
		return false
	}
	data, err := deps.readFile(filepath.Join(dir, gateway.RunStateFileName))
	if err != nil {
		return false
	}
	var state gateway.RunState
	if json.Unmarshal(data, &state) != nil {
		return false
	}
	return state.Port == port
}

// doctorTool is the best-effort install probe for one client tool: a binary on
// PATH, known per-tool config files, or a matching VS Code extension folder.
type doctorTool struct {
	name        string
	bin         string
	configFiles []string
	extPrefixes []string
}

// doctorToolsConfig mirrors envTools (W6.1). A test asserts the two lists stay
// identical so onboarding snippets and diagnostics cannot drift.
var doctorToolsConfig = []doctorTool{
	{name: "claude", bin: "claude", configFiles: []string{".claude/settings.json", ".claude.json"}},
	{name: "codex", bin: "codex", configFiles: []string{".codex/config.toml"}},
	{name: "aider", bin: "aider", configFiles: []string{".aider.conf.yml", ".aider.conf.yaml"}},
	{name: "cline", extPrefixes: []string{"saoudrizwan.claude-dev-"}},
	{name: "roo", extPrefixes: []string{"rooveterinaryinc.roo-cline-"}},
	{name: "opencode", bin: "opencode", configFiles: []string{".config/opencode/opencode.json"}},
	{name: "qwen", bin: "qwen", configFiles: []string{".qwen/settings.json"}},
	{name: "crush", bin: "crush", configFiles: []string{".config/crush/crush.json"}},
	{name: "zed", configFiles: []string{".config/zed/settings.json", "Library/Application Support/Zed/settings.json"}},
	{name: "continue", configFiles: []string{".continue/config.yaml", ".continue/config.json"}},
	{name: "openwebui"},
	{name: "goose", bin: "goose", configFiles: []string{".config/goose/config.yaml"}},
	{name: "openhands", bin: "openhands", configFiles: []string{".openhands/config.toml"}},
	{name: "kilo", extPrefixes: []string{"kilocode.kilo-code-"}},
}

// doctorToolEnvVars are the environment overrides that carry a tool's base URL.
var doctorToolEnvVars = map[string][]string{
	"claude":    {"ANTHROPIC_BASE_URL"},
	"aider":     {"OPENAI_API_BASE", "ANTHROPIC_API_BASE"},
	"qwen":      {"OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"},
	"openwebui": {"OPENAI_API_BASE_URL"},
	"goose":     {"OPENAI_HOST", "OPENAI_BASE_PATH"},
	"openhands": {"LLM_BASE_URL"},
}

// doctorExtensionDirs are the VS Code-family extension roots checked for
// Cline/Roo. Missing directories simply skip the probe.
var doctorExtensionDirs = []string{".vscode/extensions", ".vscode-insiders/extensions", ".vscode-server/extensions"}

// doctorTools renders one base-URL hint per installed tool. Detection and
// pointedness are explicitly best-effort: a miss is a warning with the exact
// URL to configure, never a hard failure.
func doctorTools(deps doctorDeps, port int) []DoctorCheck {
	root := fmt.Sprintf("http://127.0.0.1:%d", port)
	refs := []string{
		fmt.Sprintf("127.0.0.1:%d", port),
		fmt.Sprintf("localhost:%d", port),
		fmt.Sprintf("[::1]:%d", port),
	}
	checks := make([]DoctorCheck, 0, len(doctorToolsConfig))
	for _, tool := range doctorToolsConfig {
		check := DoctorCheck{Name: doctorToolPrefix + tool.name}
		if !doctorToolInstalled(deps, tool) {
			check.Status, check.Message = doctorOK, "not detected (skipped)"
			checks = append(checks, check)
			continue
		}
		pointed, configured := doctorToolPointsAtGateway(deps, tool, refs)
		switch {
		case pointed:
			check.Status, check.Message = doctorOK, "installed; base URL points at this gateway"
		case configured:
			check.Status = doctorWarn
			check.Message = "installed; its base URL does not point at this gateway"
			check.Fix = doctorToolFix(tool.name, root)
		default:
			check.Status = doctorWarn
			check.Message = "installed; no base URL configured for this gateway"
			check.Fix = doctorToolFix(tool.name, root)
		}
		checks = append(checks, check)
	}
	return checks
}

// doctorToolInstalled reports the best-effort install probes for tool.
func doctorToolInstalled(deps doctorDeps, tool doctorTool) bool {
	if tool.bin != "" {
		if _, err := deps.lookPath(tool.bin); err == nil {
			return true
		}
	}
	home, err := deps.userHomeDir()
	if err != nil {
		return false
	}
	for _, rel := range tool.configFiles {
		if _, err := deps.readFile(filepath.Join(home, rel)); err == nil {
			return true
		}
	}
	for _, rel := range doctorExtensionDirs {
		entries, err := deps.readDir(filepath.Join(home, rel))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			for _, prefix := range tool.extPrefixes {
				if strings.HasPrefix(entry.Name(), prefix) {
					return true
				}
			}
		}
	}
	return false
}

// doctorToolPointsAtGateway scans the tool's environment overrides and known
// config files for any reference to the gateway (loopback host + port).
// configured reports whether any base URL was found at all, so doctor can tell
// "wrong URL" apart from "nothing configured yet".
func doctorToolPointsAtGateway(deps doctorDeps, tool doctorTool, refs []string) (pointed, configured bool) {
	for _, key := range doctorToolEnvVars[tool.name] {
		value := deps.getenv(key)
		if value == "" {
			continue
		}
		configured = true
		pointed = pointed || containsAny(value, refs)
	}
	home, err := deps.userHomeDir()
	if err != nil {
		return pointed, configured
	}
	for _, rel := range tool.configFiles {
		data, err := deps.readFile(filepath.Join(home, rel))
		if err != nil {
			continue
		}
		configured = true
		pointed = pointed || containsAny(string(data), refs)
	}
	return pointed, configured
}

// containsAny reports whether s contains one of the plain substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// doctorToolFix renders the exact base URL to configure for a detected tool.
func doctorToolFix(tool, root string) string {
	switch tool {
	case "claude":
		return fmt.Sprintf("run: tokenhush env claude (ANTHROPIC_BASE_URL=%s)", root)
	case "aider":
		return fmt.Sprintf("run: tokenhush env aider (OPENAI_API_BASE=%s/v1, ANTHROPIC_API_BASE=%s)", root, root)
	default:
		return fmt.Sprintf("run: tokenhush env %s (base URL %s/v1)", tool, root)
	}
}

// doctorProxyEnv warns when residual proxy variables would route loopback
// traffic through a proxy that is not told to bypass it (docs/12 §7).
func doctorProxyEnv(deps doctorDeps) DoctorCheck {
	var found []string
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if deps.getenv(key) != "" {
			found = append(found, key)
		}
	}
	if len(found) == 0 {
		return DoctorCheck{
			Name:    doctorCheckProxyEnv,
			Status:  doctorOK,
			Message: "no proxy environment variables set (loopback traffic stays direct)",
		}
	}
	noProxy := deps.getenv("NO_PROXY") + "," + deps.getenv("no_proxy")
	if containsAny(noProxy, []string{"*", "127.0.0.1", "localhost", "::1"}) {
		return DoctorCheck{
			Name:    doctorCheckProxyEnv,
			Status:  doctorOK,
			Message: "proxy forward set (" + strings.Join(found, ", ") + "); NO_PROXY covers loopback",
		}
	}
	return DoctorCheck{
		Name:    doctorCheckProxyEnv,
		Status:  doctorWarn,
		Message: "proxy variables (" + strings.Join(found, ", ") + ") may intercept loopback requests",
		Fix:     "add 127.0.0.1,localhost,::1 to NO_PROXY",
	}
}

// renderDoctorHuman prints the check list plus a one-line summary.
func renderDoctorHuman(w io.Writer, report DoctorReport, failures, warnings int) {
	fmt.Fprintf(w, "tokenhush doctor (%s/%s, shell: %s)\n", report.OS, report.Arch, report.Shell)
	oks := 0
	for _, c := range report.Checks {
		fmt.Fprintf(w, "%-6s %-14s %s\n", "["+c.Status+"]", c.Name, c.Message)
		if c.Fix != "" {
			fmt.Fprintf(w, "%-6s %-14s fix: %s\n", "", "", c.Fix)
		}
		if c.Status == doctorOK {
			oks++
		}
	}
	fmt.Fprintf(w, "tokenhush doctor: %d ok, %d warning(s), %d failure(s)\n", oks, warnings, failures)
	if failures > 0 {
		fmt.Fprintln(w, "tokenhush doctor: critical problems found; fix the failures above before `tokenhush run`")
	}
}

// writeDoctorJSON emits the report as stable, indented JSON followed by a
// newline.
func writeDoctorJSON(w io.Writer, report DoctorReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
