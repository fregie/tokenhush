package redact

// knownStructuralIdentifierExemptions is the canonical honesty list for the
// high_entropy structural exemptions. It mirrors
// testdata/known_structural_exemptions.txt, the documentation artifact the
// security documentation cites; a test asserts the two stay byte-for-byte
// equal, so neither side can drift from the other.
//
// The exemptions are precision measures, not verdicts that these runs are safe:
// each is a documented skip, and together they open one narrow gap. A secret
// that happens to fit one of the grammars below is not redacted by
// high_entropy. If the engine already knows the secret, the outbound re-check
// still refuses the request (see StructuralIdentifierContains and the egress
// re-check); an unknown secret in that shape is the residual risk this list
// records.
var knownStructuralIdentifierExemptions = []string{
	"call_ + 16 or more of [A-Za-z0-9_-] (OpenAI tool-call id)",
	"toolu_ + 16 or more of [A-Za-z0-9_-] (Anthropic tool-use id)",
	"chatcmpl- + 16 or more of [A-Za-z0-9] (OpenAI chat-completion id)",
	"msg_ + 16 or more of [A-Za-z0-9] (Anthropic message id)",
	"resp_ + 16 or more of [A-Za-z0-9] (OpenAI response id)",
	"data: + <mime>[;param];base64, + a run of 28 or more of [A-Za-z0-9+/=_-] immediately after the marker (data-URI payload: an image or attachment body, not a credential)",
	"a base64-alphabet run of 128 or more of [A-Za-z0-9+/=_-] (opaque payload; real credentials are short, while multimodal and attachment bodies are long)",
	"an absolute path starting with / and using path characters, containing a hex segment of 32 or more of [0-9a-fA-F] (hash-addressed artifact path)",
	"a secret that fits one of the grammars above is not redacted by high_entropy; a known secret inside such a run is still refused by the outbound re-check, an unknown one is the recorded residual risk",
}

// KnownStructuralIdentifierExemptions returns a copy of the run shapes
// high_entropy deliberately does not treat as secrets: provider structural
// identifiers, data-URI payloads, payload-length base64 runs and
// hash-addressed artifact paths.
//
// Callers that must describe the detector's limits — the security
// documentation, for example — should cite this list rather than restate it, so
// the code and the prose cannot diverge. The list is not a claim that everything
// else is covered: an entry marks an explicit exemption, and the surrounding
// detector rules are unchanged.
func KnownStructuralIdentifierExemptions() []string {
	out := make([]string, len(knownStructuralIdentifierExemptions))
	copy(out, knownStructuralIdentifierExemptions)
	return out
}
