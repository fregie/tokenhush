package redact

// Exported finding-type names. extension.Finding.Type is the wire-visible
// classification of a detector finding; these constants mirror the unexported
// typeX values in detectors.go verbatim so layers outside pkg/redact can
// select detector types without hard-coded string literals. The pkg/proxy
// key-position fail-closed check is the first such consumer: it keeps
// {api_key, jwt, private_key} and drops credit_card/email/high_entropy at
// object-key positions (see pkg/proxy/keyguard.go).
//
// The values are frozen by docs/security.md's detector table; changing a value
// is a deliberate, version-reviewed contract change, not a silent drift.
const (
	// FindingTypeAPIKey is the type reported by the prefix detector.
	FindingTypeAPIKey = typeAPIKey
	// FindingTypeHighEntropy is the type reported by the high-entropy detector.
	FindingTypeHighEntropy = typeHighEntropy
	// FindingTypeJWT is the type reported by the JWT detector.
	FindingTypeJWT = typeJWT
	// FindingTypePrivateKey is the type reported by the private-key detector.
	FindingTypePrivateKey = typePrivateKey
)
