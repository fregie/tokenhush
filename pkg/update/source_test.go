package update

import (
	"strings"
	"testing"
)

// TestDetectSource 覆盖各安装来源与平台差异。探测是纯函数：GOOS、可执行文件
// 路径、环境与 home 全部注入，因此可在任意宿主上断言 darwin/linux/windows 行为。
func TestDetectSource(t *testing.T) {
	tests := []struct {
		name string
		goos string
		exe  string
		home string
		env  map[string]string
		want SourceKind
	}{
		{
			name: "darwin homebrew cellar",
			goos: "darwin",
			exe:  "/opt/homebrew/Cellar/tokenhush/0.3.0/bin/tokenhush",
			home: "/Users/me",
			want: SourceBrew,
		},
		{
			name: "darwin homebrew caskroom",
			goos: "darwin",
			exe:  "/usr/local/Caskroom/tokenhush/0.3.0/tokenhush",
			home: "/Users/me",
			want: SourceBrew,
		},
		{
			name: "linux linuxbrew cellar",
			goos: "linux",
			exe:  "/home/linuxbrew/.linuxbrew/Cellar/tokenhush/0.3.0/bin/tokenhush",
			home: "/home/me",
			want: SourceBrew,
		},
		{
			name: "brew via HOMEBREW_PREFIX shim",
			goos: "darwin",
			exe:  "/opt/homebrew/bin/tokenhush",
			home: "/Users/me",
			env:  map[string]string{"HOMEBREW_PREFIX": "/opt/homebrew"},
			want: SourceBrew,
		},
		{
			name: "windows scoop apps",
			goos: "windows",
			exe:  `C:\Users\me\scoop\apps\tokenhush\current\tokenhush.exe`,
			home: `C:\Users\me`,
			want: SourceScoop,
		},
		{
			name: "windows scoop shims",
			goos: "windows",
			exe:  `C:\Users\me\scoop\shims\tokenhush.exe`,
			home: `C:\Users\me`,
			want: SourceScoop,
		},
		{
			name: "windows scoop via SCOOP env",
			goos: "windows",
			exe:  `D:\tools\tokenhush\current\tokenhush.exe`,
			home: `C:\Users\me`,
			env:  map[string]string{"SCOOP": `D:\tools`},
			want: SourceScoop,
		},
		{
			name: "linux self-managed local bin",
			goos: "linux",
			exe:  "/home/me/.local/bin/tokenhush",
			home: "/home/me",
			want: SourceSelfManaged,
		},
		{
			name: "darwin self-managed local bin",
			goos: "darwin",
			exe:  "/Users/me/.local/bin/tokenhush",
			home: "/Users/me",
			want: SourceSelfManaged,
		},
		{
			name: "windows self-managed local bin",
			goos: "windows",
			exe:  `C:\Users\me\.local\bin\tokenhush.exe`,
			home: `C:\Users\me`,
			want: SourceSelfManaged,
		},
		{
			name: "system path is unknown",
			goos: "linux",
			exe:  "/usr/bin/tokenhush",
			home: "/home/me",
			want: SourceUnknown,
		},
		{
			name: "empty exe is unknown",
			goos: "linux",
			exe:  "",
			home: "/home/me",
			want: SourceUnknown,
		},
		{
			name: "missing home cannot prove self-managed",
			goos: "linux",
			exe:  "/home/me/.local/bin/tokenhush",
			home: "",
			want: SourceUnknown,
		},
		{
			name: "unknown when nothing matches",
			goos: "windows",
			exe:  `C:\Program Files\Tokenhush\tokenhush.exe`,
			home: `C:\Users\me`,
			want: SourceUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			got := detectSource(tt.goos, tt.exe, getenv, tt.home)
			if got.Kind != tt.want {
				t.Fatalf("detectSource(%q, %q, env, %q).Kind = %q, want %q",
					tt.goos, tt.exe, tt.home, got.Kind, tt.want)
			}
			if got.Exe != tt.exe {
				t.Errorf("detectSource Exe = %q, want the input path %q", got.Exe, tt.exe)
			}
		})
	}
}

// TestDetectSourceGetenvNilIsSafe 断言 getenv 为 nil 时探测不 panic 且安全降级。
func TestDetectSourceGetenvNilIsSafe(t *testing.T) {
	got := detectSource("linux", "/usr/bin/tokenhush", nil, "/home/me")
	if got.Kind != SourceUnknown {
		t.Fatalf("nil getenv Kind = %q, want %q", got.Kind, SourceUnknown)
	}
}

// TestPlanForBrewDelegatesToManager 断言 brew 场景只委派包管理器，命令里绝不
// 出现运行中的二进制路径（即绝不自替换）。
func TestPlanForBrewDelegatesToManager(t *testing.T) {
	exe := "/opt/homebrew/Cellar/tokenhush/0.3.0/bin/tokenhush"
	plan := PlanFor(Source{Kind: SourceBrew, Exe: exe}, "tokenhush", false)
	if plan.Action != ActionBrewUpgrade {
		t.Fatalf("Action = %q, want %q", plan.Action, ActionBrewUpgrade)
	}
	want := []string{"brew", "upgrade", "--cask", "tokenhush"}
	if strings.Join(plan.Command, " ") != strings.Join(want, " ") {
		t.Fatalf("Command = %v, want %v", plan.Command, want)
	}
	for _, arg := range plan.Command {
		if arg == exe {
			t.Fatalf("brew command must not reference the running binary: %v", plan.Command)
		}
	}
	if !strings.Contains(plan.Message, "brew upgrade --cask tokenhush") {
		t.Errorf("message should name the manager command, got %q", plan.Message)
	}
}

// TestPlanForScoopDelegatesToManager 断言 scoop 场景委派给 scoop update。
func TestPlanForScoopDelegatesToManager(t *testing.T) {
	plan := PlanFor(Source{Kind: SourceScoop, Exe: `C:\Users\me\scoop\shims\tokenhush-pro.exe`}, "tokenhush-pro", false)
	if plan.Action != ActionScoopUpdate {
		t.Fatalf("Action = %q, want %q", plan.Action, ActionScoopUpdate)
	}
	want := "scoop update tokenhush-pro"
	if strings.Join(plan.Command, " ") != want {
		t.Fatalf("Command = %v, want %q", plan.Command, want)
	}
	if !strings.Contains(plan.Message, want) {
		t.Errorf("message should name the manager command, got %q", plan.Message)
	}
}

// TestPlanForSelfManagedIsNoticeOnly 断言 self-managed 只给提示：无命令、无下载。
func TestPlanForSelfManagedIsNoticeOnly(t *testing.T) {
	plan := PlanFor(Source{Kind: SourceSelfManaged, Exe: "/home/me/.local/bin/tokenhush"}, "tokenhush", false)
	if plan.Action != ActionSelfManaged {
		t.Fatalf("Action = %q, want %q", plan.Action, ActionSelfManaged)
	}
	if plan.Command != nil {
		t.Fatalf("self-managed must not run a command, got %v", plan.Command)
	}
	if !strings.Contains(plan.Message, "later release") {
		t.Errorf("self-managed notice must mention the later release, got %q", plan.Message)
	}
}

// TestPlanForUnknownGivesManualGuidance 断言未知来源给出手动升级指引。
func TestPlanForUnknownGivesManualGuidance(t *testing.T) {
	plan := PlanFor(Source{Kind: SourceUnknown, Exe: "/usr/bin/tokenhush"}, "tokenhush", false)
	if plan.Action != ActionManual {
		t.Fatalf("Action = %q, want %q", plan.Action, ActionManual)
	}
	if plan.Command != nil {
		t.Fatalf("unknown source must not run a command, got %v", plan.Command)
	}
	for _, want := range []string{"brew upgrade --cask tokenhush", "scoop update tokenhush"} {
		if !strings.Contains(plan.Message, want) {
			t.Errorf("manual guidance should mention %q, got %q", want, plan.Message)
		}
	}
}

// TestPlanForCheckNeverCarriesACommand 断言 --check 计划绝不带可执行命令，且
// 说明了来源与"未做任何改动"。这是"`--check` 不安装"的结构性保证。
func TestPlanForCheckNeverCarriesACommand(t *testing.T) {
	for _, kind := range []SourceKind{SourceBrew, SourceScoop, SourceSelfManaged, SourceUnknown} {
		plan := PlanFor(Source{Kind: kind, Exe: "/x/tokenhush"}, "tokenhush", true)
		if plan.Action != ActionCheck {
			t.Errorf("%s check Action = %q, want %q", kind, plan.Action, ActionCheck)
		}
		if plan.Command != nil {
			t.Errorf("%s check must not carry a command, got %v", kind, plan.Command)
		}
		if !strings.Contains(plan.Message, "no changes") {
			t.Errorf("%s check message must state no changes, got %q", kind, plan.Message)
		}
	}
}
