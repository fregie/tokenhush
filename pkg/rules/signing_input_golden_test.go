package rules

// Code generated from the Pro shared parity vectors
// (scripts/signing-parity-vectors.json, itself derived from the Python issuer
// scripts/rules-manifest.py). Do not edit by hand: the expected hex pins the
// exact cross-language signing input, so any drift in this package's projection
// fails here. Regenerate with scripts/check-signing-parity.sh's vectors.

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// signingGolden pins one document kind's exact signing-input bytes.
type signingGolden struct {
	id   string
	kind string
	doc  string
	want string
}

var signingGoldenVectors = []signingGolden{
	{"rules-revocations-empty", "revocations", `{"channel":"stable","serial":1,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[]}`, "746f6b656e687573682d72756c65732d7265766f636174696f6e732d76310a34666464323765373263666434336563646233326436376239313335303830383434373536303130373365393537643336643839666332663538306337643665"},
	{"rules-revocations-published-live", "revocations", `{"channel":"stable","serial":1,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[]}`, "746f6b656e687573682d72756c65732d7265766f636174696f6e732d76310a34666464323765373263666434336563646233326436376239313335303830383434373536303130373365393537643336643839666332663538306337643665"},
	{"rules-revocations-nonempty", "revocations", `{"channel":"stable","serial":2,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[9,2,5]}`, "746f6b656e687573682d72756c65732d7265766f636174696f6e732d76310a64383532666431313731393763383764373330336566663961663034303336306463303638343635373039306461343863623266633930613832626239306661"},
	{"rules-manifest-empty", "manifest", `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":1,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","bundle_sha256":"9feaf199f64436846911f45c8dee377367d52dbc6277191a1cf740e4e535c2a3","bundle":"rules/stable/1.json","revoked_serials":[]}`, "746f6b656e687573682d72756c65732d6d616e69666573742d76310a38386466343935656166646633393665666164353262323038353830313866366266303662373631663363303630396262643666396639313330633366316534"},
	{"rules-manifest-nonempty", "manifest", `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":3,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","bundle_sha256":"9feaf199f64436846911f45c8dee377367d52dbc6277191a1cf740e4e535c2a3","bundle":"rules/stable/3.json","revoked_serials":[4,1]}`, "746f6b656e687573682d72756c65732d6d616e69666573742d76310a32633039663332333731313332313866643232333235343061653039666133306537636239343634633366343063663962306639666138363964616437663731"},
	{"rules-pack-minimal", "pack", `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":2,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z"}`, "746f6b656e687573682d72756c65732d7061636b2d76310a66646234303763386636326437316564353863626361393330363233396130356339646232386131356666356364363230663230363466383565343632343732"},
	{"rules-pack-rich", "pack", `{"channel":"stable","schema_version":1,"min_binary_version":"0.3.0","serial":4,"key_id":"rules-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","detectors":{"email":true,"prefix":true},"disabled_categories":["internal_only"],"allowlist":["example.com"],"blocklist":["TOKENHUSH_BLOCK"],"rules":[{"id":"proj","type":"regex","pattern":"PROJ-[0-9]{4,}","action":"warn","confidence":0.85},{"id":"secret","type":"keyword","keywords":["secret","token"],"action":"block","case_sensitive":true,"allowlist":["not-a-secret"]}]}`, "746f6b656e687573682d72756c65732d7061636b2d76310a34343030653036306661343232613836643034353234626663633233373931396438353432646637613336356664343661376564393639393738343163383134"},
}

// TestSigningInputGolden locks each document kind's signing input to the exact
// hex shared with the Python issuer. An empty revoked list must render as `[]`,
// never `null`, so the published revocation document keeps verifying.
func TestSigningInputGolden(t *testing.T) {
	for _, tc := range signingGoldenVectors {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			raw := []byte(tc.doc)
			var input []byte
			switch tc.kind {
			case "revocations":
				var r RevocationList
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				input = RevocationSigningInput(r)
			case "manifest":
				var m Manifest
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				input = ManifestSigningInput(m)
			case "pack":
				var p Pack
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				input = PackSigningInput(p)
			default:
				t.Fatalf("unknown kind %q", tc.kind)
			}
			if got := hex.EncodeToString(input); got != tc.want {
				t.Fatalf("signing input drifted for %s:\n got %s\nwant %s", tc.id, got, tc.want)
			}
		})
	}
}
