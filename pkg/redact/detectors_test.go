package redact

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// builtinDetectors returns a fresh set of the six built-in inspectors.
func builtinDetectors() []extension.Inspector {
	return []extension.Inspector{
		NewPrefixDetector(),
		NewHighEntropyDetector(),
		NewJWTDetector(),
		NewPrivateKeyDetector(),
		NewLuhnDetector(),
		NewEmailDetector(),
	}
}

// join assembles credential-shaped test samples from fragments at runtime so
// no contiguous key literal ever appears in this source file (gitleaks).
func join(parts ...string) string { return strings.Join(parts, "") }

// docOf builds a content-phase document with one leaf per content string.
func docOf(phase extension.Phase, contents ...string) *extension.Document {
	leaves := make([]extension.Leaf, len(contents))
	for i, c := range contents {
		leaves[i] = extension.Leaf{
			Path:    fmt.Sprintf("#/messages/%d/content", i),
			Content: []byte(c),
			Len:     len(c),
		}
	}
	return &extension.Document{Phase: phase, Tool: "test", Leaves: leaves}
}

func mustFindings(t *testing.T, insp extension.Inspector, doc *extension.Document) []extension.Finding {
	t.Helper()
	got, err := insp.Inspect(doc)
	if err != nil {
		t.Fatalf("%s: Inspect() error = %v", insp.ID(), err)
	}
	return got
}

// spanIn returns the exact span of sample inside content, so every expectation
// is anchored to the real offsets rather than hand-counted numbers.
func spanIn(t *testing.T, content, sample string) span {
	t.Helper()
	i := strings.Index(content, sample)
	if i < 0 {
		t.Fatalf("sample %q not found in %q", sample, content)
	}
	return span{start: i, end: i + len(sample)}
}

// assertSpans asserts the exact finding shape: offsets, type, confidence,
// action, plugin id and leaf index.
func assertSpans(t *testing.T, insp extension.Inspector, content string, wants []span, wantType string, wantConfidence float64) {
	t.Helper()
	got := mustFindings(t, insp, docOf(extension.RequestContent, content))
	if len(got) != len(wants) {
		t.Fatalf("%s: findings = %d, want %d: %#v", insp.ID(), len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		if g.LeafIndex != 0 || g.Start != w.start || g.End != w.end ||
			g.Type != wantType || g.Confidence != wantConfidence ||
			g.Action != extension.Redact || g.PluginID != insp.ID() {
			t.Errorf("%s: finding[%d] = %+v, want {leaf:0 start:%d end:%d type:%q confidence:%v action:%q plugin:%q}",
				insp.ID(), i, g, w.start, w.end, wantType, wantConfidence, extension.Redact, insp.ID())
		}
	}
}

type detectorCase struct {
	name    string
	content string
	found   []string
}

func runDetectorCases(t *testing.T, insp extension.Inspector, wantType string, wantConfidence float64, cases []detectorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wants := make([]span, 0, len(tc.found))
			for _, sample := range tc.found {
				wants = append(wants, spanIn(t, tc.content, sample))
			}
			assertSpans(t, insp, tc.content, wants, wantType, wantConfidence)
		})
	}
}

// pseudoRandom builds a deterministic high-entropy string over the base62
// alphabet. Samples are generated at runtime so no token-shaped literal is
// committed.
func pseudoRandom(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	state := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		state += 0x9E3779B97F4A7C15
		z := state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		z ^= z >> 31
		out[i] = alphabet[z%62]
	}
	return string(out)
}

// prefix samples.
var (
	openAIKey    = join("sk-", "proj-", strings.Repeat("T3stOnly", 2), "Key012")
	anthropicKey = join("sk-", "ant-", strings.Repeat("T3stOnly", 3))
	awsKey       = join("AK", "IA", "A1B2C3D4E5F6G7H8")
	githubKey    = join("ghp_", strings.Repeat("T3stToken", 4))
	githubPat    = join("github_pat_", strings.Repeat("T3st", 9))
	gitlabKey    = join("glpat-", strings.Repeat("T3stOnly", 3))
	slackKey     = join("xoxb-", "123456789012-", strings.Repeat("T3stOnly", 2))
	stripeKey    = join("sk_", "live_", strings.Repeat("T3stOnly", 2))
	googleKey    = join("AIza", strings.Repeat("T3stOnly12", 3), "T3st1")
	oauthKey     = join("ya29.", strings.Repeat("T3stOnly", 3))
	npmKey       = join("npm_", strings.Repeat("T3stOnly12", 4))
	pypiKey      = join("pypi-", strings.Repeat("T3stOnly", 3))
	sendgridKey  = join("SG.", strings.Repeat("T3stOnly", 2), ".", strings.Repeat("T3stOnly", 4))
	hfKey        = join("hf_", strings.Repeat("T3stOnly", 3))
)

func TestPrefixDetector(t *testing.T) {
	det := NewPrefixDetector()
	runDetectorCases(t, det, typeAPIKey, prefixConfidence, []detectorCase{
		{name: "openai project key", content: "OPENAI_API_KEY=" + openAIKey + "\n", found: []string{openAIKey}},
		{name: "anthropic key in json", content: `{"api_key":"` + anthropicKey + `"}`, found: []string{anthropicKey}},
		{name: "aws access key", content: "aws_access_key_id = " + awsKey, found: []string{awsKey}},
		{name: "github token", content: "Authorization: token " + githubKey, found: []string{githubKey}},
		{name: "github fine grained pat", content: "GH_PAT=" + githubPat, found: []string{githubPat}},
		{name: "gitlab pat", content: "GITLAB_TOKEN=" + gitlabKey, found: []string{gitlabKey}},
		{name: "slack bot token", content: "SLACK_TOKEN=" + slackKey, found: []string{slackKey}},
		{name: "stripe live secret", content: "STRIPE_KEY=" + stripeKey, found: []string{stripeKey}},
		{name: "google api key", content: "GOOGLE_API_KEY=" + googleKey, found: []string{googleKey}},
		{name: "google oauth token", content: "access_token=" + oauthKey, found: []string{oauthKey}},
		{name: "npm token", content: "NPM_TOKEN=" + npmKey, found: []string{npmKey}},
		{name: "pypi token", content: "PYPI_TOKEN=" + pypiKey, found: []string{pypiKey}},
		{name: "sendgrid key", content: "SENDGRID_KEY=" + sendgridKey, found: []string{sendgridKey}},
		{name: "hugging face token", content: "HF_TOKEN=" + hfKey, found: []string{hfKey}},
		{name: "two keys in one leaf", content: openAIKey + " and " + awsKey, found: []string{openAIKey, awsKey}},
		{name: "surrounded by punctuation", content: "[" + gitlabKey + "]", found: []string{gitlabKey}},

		{name: "no key", content: "just some ordinary text"},
		{name: "empty", content: ""},
		{name: "sk prefix too short", content: "sk-short"},
		{name: "sk prefix with 12 chars", content: join("sk-", strings.Repeat("T3st", 3))},
		{name: "aws key 14 chars after prefix", content: join("AK", "IA", "A1B2C3D4E5F6G7")},
		{name: "aws key embedded after token byte", content: "x" + awsKey},
		{name: "aws key extended by trailing char", content: awsKey + "x"},
		{name: "github token too short", content: join("ghp_", strings.Repeat("T3stOnly", 2), "T3s")},
		{name: "google api key 30 chars", content: join("AIza", strings.Repeat("T3stOnly12", 3))},
		{name: "npm token 20 chars", content: join("npm_", strings.Repeat("T3stOnly12", 2))},
		{name: "ya29 without dot", content: join("ya29", strings.Repeat("T3stOnly", 3))},
		{name: "pypi without dash", content: join("pypi", strings.Repeat("T3stOnly", 3))},
		{name: "sendgrid second segment too short", content: join("SG.", strings.Repeat("T3stOnly", 2), ".", strings.Repeat("T3st", 3))},
		{name: "ordinary hyphenated words", content: "risk-free refactoring is not a secret"},
		{name: "aws-like lowercase text", content: "akia a1b2c3d4e5f6g7h8"},
	})
}

func TestHighEntropyDetector(t *testing.T) {
	det := NewHighEntropyDetector()
	random40 := pseudoRandom(40)
	random28 := pseudoRandom(28)
	random27 := pseudoRandom(27)

	// The hex sample contains each hex symbol exactly twice: its Shannon
	// entropy is exactly 4.0 bits/char, so only the pure-hex exclusion can
	// reject it. Without that rule this test fails.
	hexEqualEntropy := join("0123456789abcdef", "f0e1d2c3b4a59687")
	// The letters sample has entropy above 4.0 bits/char and no digit, so only
	// the digit-or-punctuation requirement can reject it.
	lettersOnly := "abcdefghijklmnopqrstuvwxyzab"
	uuidLike := join("123e4567-", "e89b-12d3-", "a456-426614174000")

	runDetectorCases(t, det, typeHighEntropy, highEntropyConfidence, []detectorCase{
		{name: "random 40 chars", content: "blob " + random40 + " end", found: []string{random40}},
		{name: "random 28 chars at floor", content: "blob " + random28 + " end", found: []string{random28}},
		{name: "base64 punctuation", content: "data " + random40 + "+/=", found: []string{random40 + "+/="}},

		{name: "random 27 chars below floor", content: random27},
		{name: "pure hex with entropy 4.0", content: hexEqualEntropy},
		{name: "uuid", content: uuidLike},
		{name: "letters only above entropy floor", content: lettersOnly},
		{name: "long repeated word", content: strings.Repeat("antidisestablishment", 2)},
		{name: "empty", content: ""},
		{name: "short random", content: "T3stOnlyAb1"},
	})
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestJWTDetector(t *testing.T) {
	det := NewJWTDetector()
	header := b64url(`{"alg":"HS256","typ":"JWT"}`)
	payload := b64url(`{"sub":"T3st","exp":4070908800}`)
	sig := b64url("T3stSignature")
	jwt := join(header, ".", payload, ".", sig)
	headerNoAlg := b64url(`{"typ":"JWT"}`)

	runDetectorCases(t, det, typeJWT, jwtConfidence, []detectorCase{
		{name: "bearer token", content: "Authorization: Bearer " + jwt + "\n", found: []string{jwt}},
		{name: "bare jwt", content: jwt, found: []string{jwt}},
		{name: "alg none header", content: join(b64url(`{"alg":"none"}`), ".", payload, ".", sig), found: []string{join(b64url(`{"alg":"none"}`), ".", payload, ".", sig)}},

		{name: "not a jwt", content: "a.b.c"},
		{name: "header without alg", content: headerNoAlg + ".x.y"},
		{name: "two segments", content: join(header, ".", payload)},
		{name: "four segments", content: join(header, ".", payload, ".", sig, ".", "extra")},
		{name: "trailing dot", content: jwt + "."},
		{name: "embedded after token byte", content: "x" + jwt},
		{name: "header not json", content: join(b64url("hello"), ".x.y")},
		{name: "header only", content: header},
		{name: "empty", content: ""},
	})
}

func TestPrivateKeyDetector(t *testing.T) {
	det := NewPrivateKeyDetector()
	headerRSA := join("-----BEGIN ", "RSA ", "PRIVATE KEY-----")
	footerRSA := join("-----END ", "RSA ", "PRIVATE KEY-----")
	headerEC := join("-----BEGIN ", "EC ", "PRIVATE KEY-----")
	footerEC := join("-----END ", "EC ", "PRIVATE KEY-----")
	headerOpenSSH := join("-----BEGIN ", "OPENSSH ", "PRIVATE KEY-----")
	footerOpenSSH := join("-----END ", "OPENSSH ", "PRIVATE KEY-----")
	headerEncrypted := join("-----BEGIN ", "ENCRYPTED ", "PRIVATE KEY-----")
	headerPGP := join("-----BEGIN ", "PGP ", "PRIVATE KEY BLOCK-----")
	footerPGP := join("-----END ", "PGP ", "PRIVATE KEY BLOCK-----")
	body := strings.Repeat("MIIB", 16)

	rsaBlock := headerRSA + "\n" + body + "\n" + footerRSA
	ecBlock := headerEC + "\n" + body + "\n" + footerEC
	openSSHBlock := headerOpenSSH + "\n" + body + "\n" + footerOpenSSH
	pgpBlock := headerPGP + "\n" + body + "\n" + footerPGP

	runDetectorCases(t, det, typePrivateKey, privateKeyConfidence, []detectorCase{
		{name: "rsa block extends through end marker", content: "before\n" + rsaBlock + "\nafter", found: []string{rsaBlock}},
		{name: "ec block", content: ecBlock, found: []string{ecBlock}},
		{name: "openssh block", content: openSSHBlock, found: []string{openSSHBlock}},
		{name: "pgp block", content: pgpBlock, found: []string{pgpBlock}},
		{name: "header only without end marker", content: "x " + headerEncrypted + " y", found: []string{headerEncrypted}},
		{name: "two blocks", content: rsaBlock + "\n" + ecBlock, found: []string{rsaBlock, ecBlock}},

		{name: "public key", content: join("-----BEGIN ", "PUBLIC ", "KEY-----")},
		{name: "rsa public key", content: join("-----BEGIN ", "RSA ", "PUBLIC KEY-----")},
		{name: "certificate", content: join("-----BEGIN ", "CERTIFICATE-----")},
		{name: "four leading dashes", content: join("----BEGIN ", "RSA ", "PRIVATE KEY-----")},
		{name: "missing final dash", content: join("-----BEGIN ", "RSA ", "PRIVATE KEY----")},
		{name: "lowercase marker", content: join("-----BEGIN ", "rsa ", "PRIVATE KEY-----")},
		{name: "plain words", content: "PRIVATE KEY"},
		{name: "empty", content: ""},
	})
}

func TestLuhnDetector(t *testing.T) {
	det := NewLuhnDetector()
	visa16 := "4111 1111 1111 1111"
	mastercard := "5500-0000-0000-0004"
	amex15 := "378282246310005"
	discover := "6011111111111117"
	visa13 := "4222222222222"
	visa19 := "4000000000000000006"

	runDetectorCases(t, det, typeCreditCard, luhnConfidence, []detectorCase{
		{name: "visa 16 grouped by spaces", content: "card: " + visa16 + ".", found: []string{visa16}},
		{name: "mastercard grouped by dashes", content: mastercard, found: []string{mastercard}},
		{name: "amex 15", content: "[" + amex15 + "]", found: []string{amex15}},
		{name: "discover", content: discover, found: []string{discover}},
		{name: "visa 13", content: "x " + visa13 + " y", found: []string{visa13}},
		{name: "visa 19", content: visa19, found: []string{visa19}},
		{name: "two cards", content: "a " + visa16 + " b " + mastercard + " c", found: []string{visa16, mastercard}},

		{name: "luhn invalid", content: "1234 5678 9012 3456"},
		{name: "all zeros", content: "0000 0000 0000 0000"},
		{name: "all ones", content: "1111 1111 1111 1111"},
		{name: "13 digits invalid", content: "1234567890123"},
		{name: "12 digits too short", content: "4111 1111 1111"},
		{name: "20 digits too long", content: "4111 1111 1111 1111 1111"},
		{name: "phone number", content: "+1 (555) 123-4567"},
		{name: "empty", content: ""},
	})
}

func TestEmailDetector(t *testing.T) {
	det := NewEmailDetector()
	runDetectorCases(t, det, typeEmail, emailConfidence, []detectorCase{
		{name: "simple address", content: "contact user@example.com please", found: []string{"user@example.com"}},
		{name: "tagged subdomain address", content: "first.last+tag@sub.example.co.uk", found: []string{"first.last+tag@sub.example.co.uk"}},
		{name: "percent and dash local part", content: "a_b%c-d@my-host.example.io", found: []string{"a_b%c-d@my-host.example.io"}},
		{name: "angle brackets with sentence period", content: "ping <ops@team.example.org>.", found: []string{"ops@team.example.org"}},
		{name: "two addresses", content: "a@example.com, b@example.net", found: []string{"a@example.com", "b@example.net"}},

		{name: "no tld", content: "foo@bar"},
		{name: "decorator", content: "@decorator"},
		{name: "localhost", content: "user@localhost"},
		{name: "no at sign", content: "not.an.email"},
		{name: "double dot domain", content: "foo@bar..com"},
		{name: "trailing dot tld", content: "foo@bar."},
		{name: "double at", content: "foo@@bar.com"},
		{name: "one letter tld", content: "user@example.c"},
		{name: "empty", content: ""},
	})
}

func TestAllowlistSuppressesDetection(t *testing.T) {
	allowed := "ops@corp.example"

	t.Run("allowlisted literal never flagged", func(t *testing.T) {
		det := NewEmailDetector(WithAllowlist(allowed))
		content := "ping " + allowed + " then dev@corp.example"
		got := mustFindings(t, det, docOf(extension.RequestContent, content))
		want := spanIn(t, content, "dev@corp.example")
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end {
			t.Fatalf("findings = %#v, want only dev@corp.example at [%d,%d)", got, want.start, want.end)
		}
	})

	t.Run("allowlist applies to prefix detector", func(t *testing.T) {
		det := NewPrefixDetector(WithAllowlist(openAIKey))
		content := openAIKey + " and " + awsKey
		got := mustFindings(t, det, docOf(extension.RequestContent, content))
		want := spanIn(t, content, awsKey)
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end || got[0].Type != typeAPIKey {
			t.Fatalf("findings = %#v, want only the non-allowlisted key at [%d,%d)", got, want.start, want.end)
		}
	})

	t.Run("multiple literals and repeated occurrences", func(t *testing.T) {
		det := NewEmailDetector(WithAllowlist("a@x.co", "b@x.co"))
		content := "a@x.co b@x.co c@x.co a@x.co"
		got := mustFindings(t, det, docOf(extension.RequestContent, content))
		want := spanIn(t, content, "c@x.co")
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end {
			t.Fatalf("findings = %#v, want only c@x.co at [%d,%d)", got, want.start, want.end)
		}
	})

	t.Run("literal that does not cover the finding does not suppress it", func(t *testing.T) {
		det := NewEmailDetector(WithAllowlist("corp.example"))
		content := "dev@corp.example"
		got := mustFindings(t, det, docOf(extension.RequestContent, content))
		if len(got) != 1 {
			t.Fatalf("findings = %#v, want 1 (literal is a substring of the finding)", got)
		}
	})

	t.Run("exact literal occurrence suppresses", func(t *testing.T) {
		det := NewEmailDetector(WithAllowlist("dev@corp.example"))
		got := mustFindings(t, det, docOf(extension.RequestContent, "dev@corp.example"))
		if len(got) != 0 {
			t.Fatalf("findings = %#v, want none", got)
		}
	})

	t.Run("empty literals and nil option suppress nothing", func(t *testing.T) {
		for _, det := range []extension.Inspector{
			NewEmailDetector(WithAllowlist("", "")),
			NewEmailDetector(nil),
			NewEmailDetector(WithAllowlist()),
		} {
			got := mustFindings(t, det, docOf(extension.RequestContent, "user@example.com"))
			if len(got) != 1 {
				t.Fatalf("%s: findings = %#v, want 1", det.ID(), got)
			}
		}
	})
}

func TestBuiltinDetectorsRegister(t *testing.T) {
	reg := extension.NewRegistry()
	for _, det := range builtinDetectors() {
		if err := reg.Register(det); err != nil {
			t.Fatalf("Register(%s) error = %v", det.ID(), err)
		}
	}
	wantIDs := []string{"email", "high_entropy", "jwt", "luhn", "prefix", "private_key"}
	for _, phase := range []extension.Phase{extension.RequestContent, extension.ResponseContent} {
		got := reg.Inspectors(phase)
		ids := make([]string, len(got))
		for i, insp := range got {
			ids[i] = insp.ID()
		}
		if !reflect.DeepEqual(ids, wantIDs) {
			t.Errorf("Inspectors(%s) ids = %v, want %v", phase, ids, wantIDs)
		}
	}
	if got := reg.Transformers(extension.ResponseContent); len(got) != 0 {
		t.Errorf("Transformers(response_content) = %v, want none", got)
	}
}

func TestDetectorsPreserveContentThroughGate(t *testing.T) {
	for _, det := range builtinDetectors() {
		caps := det.Capabilities()
		if !caps.ReadContent {
			t.Errorf("%s: ReadContent = false, want true", det.ID())
			continue
		}
		for _, phase := range caps.Phases {
			doc := docOf(phase, "user@example.com")
			view, err := extension.Gate(doc, caps)
			if err != nil {
				t.Fatalf("%s: Gate(%s) error = %v", det.ID(), phase, err)
			}
			if len(view.Leaves) != 1 || string(view.Leaves[0].Content) != "user@example.com" {
				t.Errorf("%s: Gate(%s) withheld content despite ReadContent: %#v", det.ID(), phase, view.Leaves)
			}
		}
	}
}

func TestDetectorsMalformedInput(t *testing.T) {
	t.Run("nil document", func(t *testing.T) {
		for _, det := range builtinDetectors() {
			got, err := det.Inspect(nil)
			if err != nil || got != nil {
				t.Errorf("%s: Inspect(nil) = (%#v, %v), want (nil, nil)", det.ID(), got, err)
			}
		}
	})

	t.Run("zero length leaves", func(t *testing.T) {
		doc := &extension.Document{
			Phase: extension.RequestContent,
			Leaves: []extension.Leaf{
				{Path: "missing"},
				{Path: "nil content", Content: nil},
				{Path: "empty content", Content: []byte{}},
				{Path: "zero len", Content: []byte{}, Len: 0},
			},
		}
		for _, det := range builtinDetectors() {
			got, err := det.Inspect(doc)
			if err != nil || len(got) != 0 {
				t.Errorf("%s: Inspect(empty leaves) = (%#v, %v), want no findings", det.ID(), got, err)
			}
		}
	})

	t.Run("invalid utf-8", func(t *testing.T) {
		raw := append([]byte{0xff, 0xfe, 0xc0, 0x80, 0xed, 0xa0, 0x80}, []byte(" user@example.com ")...)
		doc := &extension.Document{
			Phase:  extension.RequestContent,
			Leaves: []extension.Leaf{{Path: "binary", Content: raw, Len: len(raw)}},
		}
		for _, det := range builtinDetectors() {
			if _, err := det.Inspect(doc); err != nil {
				t.Fatalf("%s: Inspect(invalid utf-8) error = %v", det.ID(), err)
			}
		}
		got := mustFindings(t, NewEmailDetector(), doc)
		want := spanIn(t, string(raw), "user@example.com")
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end {
			t.Fatalf("email findings = %#v, want one at [%d,%d)", got, want.start, want.end)
		}
	})

	t.Run("huge leaf", func(t *testing.T) {
		content := strings.Repeat("a", 1<<20) + " user@example.com"
		doc := docOf(extension.RequestContent, content)
		for _, det := range builtinDetectors() {
			if _, err := det.Inspect(doc); err != nil {
				t.Fatalf("%s: Inspect(huge leaf) error = %v", det.ID(), err)
			}
		}
		got := mustFindings(t, NewEmailDetector(), doc)
		want := spanIn(t, content, "user@example.com")
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end {
			t.Fatalf("email findings = %#v, want one at [%d,%d)", got, want.start, want.end)
		}
	})

	t.Run("nil writer-free doc with nil leaves", func(t *testing.T) {
		doc := &extension.Document{Phase: extension.RequestContent}
		for _, det := range builtinDetectors() {
			if _, err := det.Inspect(doc); err != nil {
				t.Fatalf("%s: Inspect(no leaves) error = %v", det.ID(), err)
			}
		}
	})
}

func TestFindingsDeterministicAndOrdered(t *testing.T) {
	content0 := "User@Example.com first"
	content2 := "second@example.org"
	doc := docOf(extension.RequestContent, content0, "no addresses here", content2)

	det := NewEmailDetector()
	first := mustFindings(t, det, doc)
	second := mustFindings(t, det, doc)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("findings are not deterministic:\n%#v\n%#v", first, second)
	}

	want := []struct {
		leaf int
		span span
	}{
		{leaf: 0, span: spanIn(t, content0, "User@Example.com")},
		{leaf: 2, span: spanIn(t, content2, content2)},
	}
	if len(first) != len(want) {
		t.Fatalf("findings = %#v, want %d", first, len(want))
	}
	for i, w := range want {
		g := first[i]
		if g.LeafIndex != w.leaf || g.Start != w.span.start || g.End != w.span.end || g.PluginID != det.ID() {
			t.Errorf("finding[%d] = %+v, want {leaf:%d start:%d end:%d plugin:%q}", i, g, w.leaf, w.span.start, w.span.end, det.ID())
		}
	}

	// Multiple findings in one leaf are ordered by start.
	multi := "z@example.com a@example.com"
	got := mustFindings(t, det, docOf(extension.RequestContent, multi))
	if len(got) != 2 || got[0].Start != strings.Index(multi, "z@example.com") || got[1].Start != strings.Index(multi, "a@example.com") {
		t.Fatalf("multi findings = %#v, want ascending starts", got)
	}
	if !bytes.Equal([]byte(multi)[got[0].Start:got[0].End], []byte("z@example.com")) {
		t.Fatalf("offsets do not map back to the matched content: %#v", got[0])
	}
}
