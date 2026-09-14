package update

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
	{"update-manifest-empty", "manifest", `{"version":"0.4.0","os":"linux","arch":"amd64","url":"https://updates.tokenhush.com/dl/tokenhush_0.4.0_linux_amd64.tar.gz","sha256":"9feaf199f64436846911f45c8dee377367d52dbc6277191a1cf740e4e535c2a3","channel":"stable","serial":1,"key_id":"upd-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[],"revoked_versions":[]}`, "746f6b656e687573682d7570646174652d6d616e69666573742d76310a76657273696f6e3a302e342e300a6f733a6c696e75780a617263683a616d6436340a75726c3a68747470733a2f2f757064617465732e746f6b656e687573682e636f6d2f646c2f746f6b656e687573685f302e342e305f6c696e75785f616d6436342e7461722e677a0a7368613235363a396665616631393966363434333638343639313166343563386465653337373336376435326462633632373731393161316366373430653465353335633261330a6368616e6e656c3a737461626c650a73657269616c3a310a6b65795f69643a7570642d323032362d30390a6e6f745f6265666f72653a313738393334343030300a657870697265733a313832303838303030300a7265766f6b65645f73657269616c733a0a7265766f6b65645f76657273696f6e733a0a"},
	{"update-manifest-nonempty", "manifest", `{"version":"0.4.1","os":"linux","arch":"amd64","url":"https://updates.tokenhush.com/dl/tokenhush_0.4.1_linux_amd64.tar.gz","sha256":"9feaf199f64436846911f45c8dee377367d52dbc6277191a1cf740e4e535c2a3","channel":"stable","serial":2,"key_id":"upd-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[7,3],"revoked_versions":["0.3.9","0.3.8"]}`, "746f6b656e687573682d7570646174652d6d616e69666573742d76310a76657273696f6e3a302e342e310a6f733a6c696e75780a617263683a616d6436340a75726c3a68747470733a2f2f757064617465732e746f6b656e687573682e636f6d2f646c2f746f6b656e687573685f302e342e315f6c696e75785f616d6436342e7461722e677a0a7368613235363a396665616631393966363434333638343639313166343563386465653337373336376435326462633632373731393161316366373430653465353335633261330a6368616e6e656c3a737461626c650a73657269616c3a320a6b65795f69643a7570642d323032362d30390a6e6f745f6265666f72653a313738393334343030300a657870697265733a313832303838303030300a7265766f6b65645f73657269616c733a332c370a7265766f6b65645f76657273696f6e733a302e332e382c302e332e390a"},
	{"update-revocations-empty", "revocations", `{"channel":"stable","serial":1,"key_id":"upd-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[],"revoked_versions":[]}`, "746f6b656e687573682d7570646174652d7265766f636174696f6e732d76310a6368616e6e656c3a737461626c650a73657269616c3a310a6b65795f69643a7570642d323032362d30390a6e6f745f6265666f72653a313738393334343030300a657870697265733a313832303838303030300a7265766f6b65645f73657269616c733a0a7265766f6b65645f76657273696f6e733a0a"},
	{"update-revocations-nonempty", "revocations", `{"channel":"stable","serial":2,"key_id":"upd-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","revoked_serials":[5,1],"revoked_versions":["0.3.9"]}`, "746f6b656e687573682d7570646174652d7265766f636174696f6e732d76310a6368616e6e656c3a737461626c650a73657269616c3a320a6b65795f69643a7570642d323032362d30390a6e6f745f6265666f72653a313738393334343030300a657870697265733a313832303838303030300a7265766f6b65645f73657269616c733a312c350a7265766f6b65645f76657273696f6e733a302e332e390a"},
	{"update-keylist-two-keys", "keylist", `{"serial":1,"key_id":"root-2026-09","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z","keys":[{"key_id":"upd-2026-10","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z"},{"key_id":"upd-2026-09","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","not_before":"2026-09-14T00:00:00Z","expires":"2027-09-14T00:00:00Z"}]}`, "746f6b656e687573682d7570646174652d6b65796c6973742d76310a73657269616c3a310a6b65795f69643a726f6f742d323032362d30390a6e6f745f6265666f72653a313738393334343030300a657870697265733a313832303838303030300a6b65793a7570642d323032362d30393a414141414141414141414141414141414141414141414141414141414141414141414141414141414141413a313738393334343030303a313832303838303030300a6b65793a7570642d323032362d31303a414141414141414141414141414141414141414141414141414141414141414141414141414141414141413a313738393334343030303a313832303838303030300a"},
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
			case "manifest":
				var m Manifest
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatal(err)
				}
				input = ManifestSigningInput(m)
			case "revocations":
				var r RevocationList
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				input = RevocationSigningInput(r)
			case "keylist":
				var k KeyList
				if err := json.Unmarshal(raw, &k); err != nil {
					t.Fatal(err)
				}
				input = KeyListSigningInput(k)
			default:
				t.Fatalf("unknown kind %q", tc.kind)
			}
			if got := hex.EncodeToString(input); got != tc.want {
				t.Fatalf("signing input drifted for %s:\n got %s\nwant %s", tc.id, got, tc.want)
			}
		})
	}
}
