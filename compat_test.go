package contracts_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// The compat battery (R2.13): the tests that gate a protocol release.
// The golden wire fixtures (middleman_golden_test.go) pin the bytes;
// the tests here pin the laws a release cannot move without a
// deliberate version bump: the exactly-once key law at every nesting
// level, the version-negotiation matrix (v1 is exact-match-only), the
// refusal vocabulary's completeness, and the console tap's
// masked-versus-raw stance.

// TestStrictDecodeNestedDuplicateKeyRefusal pins the exactly-once key
// law BELOW the top level. The stdlib struct decode silently takes a
// duplicate key's last occurrence at every depth, so the strict
// decoder's key scan walks the document's object tree — nested objects
// and objects inside arrays — and refuses a second occurrence of any
// key, naming where it sat. Before R2.13 the scan stopped at the top
// level and a nested duplicate slipped through to the silent
// last-wins.
func TestStrictDecodeNestedDuplicateKeyRefusal(t *testing.T) {
	// A valid full-shape job spec (the same document minus the injected
	// duplicate decodes clean — the positive control below uses it).
	validJob := `{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
		`"image":"ghcr.io/acme/payments-ci@sha256:ababababababababababababababababababababababababababababababababab",` +
		`"command":["make","test"],` +
		`"services":[{"name":"postgres","image":"docker.io/library/postgres@sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}],` +
		`"artifact_inputs":[{"name":"sbom","reference":"ghcr.io/acme/sboms@sha256:2323232323232323232323232323232323232323232323232323232323232323"}],` +
		`"timeout_seconds":3600,` +
		`"limits":{"cpu_millicores":8000,"memory_bytes":17179869184,"disk_bytes":1099511627776},` +
		`"egress_allowlist":["registry.acme.example"],` +
		`"metering_tags":{"org":"acme","pipeline":"payments-ci"}}`

	validCancel := `{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
		`"reason":{"class":"cancelled","message":"the user pressed stop"}}`

	envJSON := `{"op":"health","op_id":"op-dup-1","deadline_unix_ms":1796932800000}`
	validHealth := `{"envelope":` + envJSON + `}`
	validClean := `{"envelope":{"op":"run_clean_cycle","op_id":"op-dup-2","deadline_unix_ms":1796932800000},` +
		`"clean":{"targets":[{"kind":"stage","ref":"/var/lib/runnermand/stages/op-1"}]}}`
	validTap := `{"reply":{"op":"tap_console","op_id":"op-dup-3","ok":true},` +
		`"stream":{"stream_id":"tap-1","job_id":"job-20261108-000001","sequence":1,"masked":true,"line":"ok","eof":false}}`

	cases := []struct {
		name    string
		doc     []byte
		decode  func([]byte) error
		wantMsg string // the position the refusal must name
	}{
		{
			name: "duplicate inside a nested object (limits)",
			doc: []byte(`{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
				`"image":"ghcr.io/acme/payments-ci@sha256:ababababababababababababababababababababababababababababababababab",` +
				`"timeout_seconds":3600,` +
				`"limits":{"cpu_millicores":8000,"cpu_millicores":2000,"memory_bytes":17179869184,"disk_bytes":1099511627776},` +
				`"egress_allowlist":["registry.acme.example"],` +
				`"metering_tags":{"org":"acme"}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeJobSpec(d); return err },
			wantMsg: `inside $.limits`,
		},
		{
			name: "duplicate inside a map object (metering_tags)",
			doc: []byte(`{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
				`"image":"ghcr.io/acme/payments-ci@sha256:ababababababababababababababababababababababababababababababababab",` +
				`"timeout_seconds":3600,` +
				`"limits":{"cpu_millicores":8000,"memory_bytes":17179869184,"disk_bytes":1099511627776},` +
				`"egress_allowlist":["registry.acme.example"],` +
				`"metering_tags":{"org":"acme","org":"acme-two"}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeJobSpec(d); return err },
			wantMsg: `inside $.metering_tags`,
		},
		{
			name: "duplicate inside an object inside an array (services[])",
			doc: []byte(`{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
				`"image":"ghcr.io/acme/payments-ci@sha256:ababababababababababababababababababababababababababababababababab",` +
				`"services":[{"name":"postgres","name":"pg","image":"docker.io/library/postgres@sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}],` +
				`"timeout_seconds":3600,` +
				`"limits":{"cpu_millicores":8000,"memory_bytes":17179869184,"disk_bytes":1099511627776},` +
				`"egress_allowlist":["registry.acme.example"],` +
				`"metering_tags":{"org":"acme"}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeJobSpec(d); return err },
			wantMsg: `inside $.services[]`,
		},
		{
			name: "duplicate inside an array element (artifact_inputs[])",
			doc: []byte(`{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
				`"image":"ghcr.io/acme/payments-ci@sha256:ababababababababababababababababababababababababababababababababab",` +
				`"artifact_inputs":[{"name":"sbom","reference":"ghcr.io/acme/sboms@sha256:2323232323232323232323232323232323232323232323232323232323232323","reference":"ghcr.io/acme/sboms@sha256:2323232323232323232323232323232323232323232323232323232323232323"}],` +
				`"timeout_seconds":3600,` +
				`"limits":{"cpu_millicores":8000,"memory_bytes":17179869184,"disk_bytes":1099511627776},` +
				`"egress_allowlist":["registry.acme.example"],` +
				`"metering_tags":{"org":"acme"}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeJobSpec(d); return err },
			wantMsg: `inside $.artifact_inputs[]`,
		},
		{
			name: "duplicate inside the cancel directive's reason",
			doc: []byte(`{"job_id":"job-20261108-000001","run_reference":"acme/payments@main:run-421","attempt":1,` +
				`"reason":{"class":"cancelled","class":"quota","message":"the user pressed stop"}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeCancelSpec(d); return err },
			wantMsg: `inside $.reason`,
		},
		{
			name:    "duplicate inside a middleman envelope",
			doc:     []byte(`{"envelope":{"op":"health","op_id":"op-dup-1","op_id":"op-dup-1b","deadline_unix_ms":1796932800000}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeHealthRequest(d); return err },
			wantMsg: `inside $.envelope`,
		},
		{
			name: "duplicate inside a clean target array element",
			doc: []byte(`{"envelope":{"op":"run_clean_cycle","op_id":"op-dup-2","deadline_unix_ms":1796932800000},` +
				`"clean":{"targets":[{"kind":"stage","kind":"container","ref":"/var/lib/runnermand/stages/op-1"}]}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeRunCleanCycleRequest(d); return err },
			wantMsg: `inside $.clean.targets[]`,
		},
		{
			name: "duplicate inside a tap stream record",
			doc: []byte(`{"reply":{"op":"tap_console","op_id":"op-dup-3","ok":true},` +
				`"stream":{"stream_id":"tap-1","stream_id":"tap-1b","job_id":"job-20261108-000001","sequence":1,"masked":true,"line":"ok","eof":false}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodeTapConsoleReply(d); return err },
			wantMsg: `inside $.stream`,
		},
		{
			name: "duplicate deep inside a delivery (the custody document)",
			doc: []byte(`{"envelope":{"op":"prepare","op_id":"op-dup-4","deadline_unix_ms":1796932800000},` +
				`"delivery":{"delivery_attempt":1,"job_id":"job-20261108-000002","run_reference":"acme/payments@main:run-422","attempt":1,` +
				`"forge":"github","start_render":"#!/bin/sh\n","fresh_registration_token":"tok-0001",` +
				`"digest_pin":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",` +
				`"artifacts":[{"name":"runner-binary","name":"runner-bin-again","reference":"rail://runners/github/2.321.0","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}}`),
			decode:  func(d []byte) error { _, err := contracts.DecodePrepareRequest(d); return err },
			wantMsg: `inside $.delivery.artifacts[]`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.decode(tc.doc)
			if err == nil {
				t.Fatalf("the decoder accepted a document with a duplicated nested key; the last-wins fold must be refused")
			}
			if !strings.Contains(err.Error(), "more than once") {
				t.Fatalf("the refusal is not the exactly-once rule: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("the refusal must name the duplicate's position %q: %v", tc.wantMsg, err)
			}
		})
	}

	// The positive controls: the same documents WITHOUT a duplicate
	// decode clean — the scan refuses duplicates, not nesting.
	t.Run("positive controls decode clean", func(t *testing.T) {
		for _, doc := range [][]byte{[]byte(validJob), []byte(validCancel), []byte(validHealth), []byte(validClean), []byte(validTap)} {
			var err error
			switch {
			case strings.Contains(string(doc), `"reason"`):
				_, err = contracts.DecodeCancelSpec(doc)
			case strings.Contains(string(doc), `"targets"`):
				_, err = contracts.DecodeRunCleanCycleRequest(doc)
			case strings.Contains(string(doc), `"stream"`):
				_, err = contracts.DecodeTapConsoleReply(doc)
			case strings.Contains(string(doc), `"envelope"`):
				_, err = contracts.DecodeHealthRequest(doc)
			default:
				_, err = contracts.DecodeJobSpec(doc)
			}
			if err != nil {
				t.Fatalf("a valid document was refused: %v (%s)", err, doc)
			}
		}
	})

	// A nested UNKNOWN field stays the strict struct decode's refusal
	// (the scan adds duplicates at depth; it does not move the
	// unknown-field law off the struct decode).
	t.Run("nested unknown field still the struct decode's refusal", func(t *testing.T) {
		_, err := contracts.DecodeHealthRequest([]byte(`{"envelope":{"op":"health","op_id":"x","deadline_unix_ms":1,"shell":"/bin/sh"}}`))
		if err == nil || !strings.Contains(err.Error(), "unknown_field") {
			t.Fatalf("a nested unknown field was not refused by the unknown_field rule: %v", err)
		}
	})

	// The vocabulary of rule names cannot drift: the duplicate refusal
	// keeps the typed rule the consumers match on.
	t.Run("duplicate refusal keeps the typed rule", func(t *testing.T) {
		err := func() error {
			_, e := contracts.DecodeHealthRequest([]byte(`{"envelope":{"op":"health","op_id":"x","op_id":"x","deadline_unix_ms":1}}`))
			return e
		}()
		errs, ok := err.(contracts.ValidationErrors)
		if !ok || len(errs) != 1 || errs[0].Rule != contracts.RuleUnknownField {
			t.Fatalf("the duplicate refusal is not the typed RuleUnknownField: %#v", err)
		}
	})
}

// TestHandshakeNegotiationMatrix pins the version-negotiation matrix:
// v1 is EXACT-MATCH-ONLY, so exactly one row accepts — equal versions —
// and every other (agent, daemon) pair refuses with the refusal
// document naming BOTH versions and the expected rule. The matrix walks
// a window of versions around ProtocolVersion so the law holds at the
// boundaries a real skew would produce, not just the fixture pair.
func TestHandshakeNegotiationMatrix(t *testing.T) {
	const window = 3
	versions := make([]int, 0, 2*window+1)
	for v := contracts.ProtocolVersion - window; v <= contracts.ProtocolVersion+window; v++ {
		if v < 1 {
			continue // protocol versions are 1-based; 0 and below are shape-invalid, not negotiable
		}
		versions = append(versions, v)
	}

	for _, agentV := range versions {
		for _, daemonV := range versions {
			name := "accept"
			if agentV != daemonV {
				name = "refuse-skew"
			}
			t.Run(name+"-agent-v"+strconv.Itoa(agentV)+"-daemon-v"+strconv.Itoa(daemonV), func(t *testing.T) {
				hello := contracts.HelloRequest{ProtocolVersion: agentV, AgentBuild: "agent-matrix"}
				rep := contracts.NegotiateHello(hello, daemonV)

				if agentV == daemonV {
					// The exact-match accept: the daemon echoes its version,
					// no refusal document.
					if !rep.Accepted || rep.ProtocolVersion != daemonV || rep.Refusal != nil {
						t.Fatalf("equal versions (%d) must accept with the echo, got %+v", agentV, rep)
					}
				} else {
					// Every skew pair refuses loudly: both versions named,
					// the expected rule named, a human message present.
					if rep.Accepted {
						t.Fatalf("skewed versions (agent %d, daemon %d) must refuse; v1 negotiates no compatible range", agentV, daemonV)
					}
					if rep.ProtocolVersion != daemonV {
						t.Fatalf("the refusal must carry the daemon's version %d, got %d", daemonV, rep.ProtocolVersion)
					}
					r := rep.Refusal
					if r == nil {
						t.Fatalf("a refused handshake carries no refusal document: %+v", rep)
					}
					if r.AgentProtocolVersion != agentV || r.DaemonProtocolVersion != daemonV {
						t.Fatalf("the refusal must name BOTH versions (agent %d, daemon %d), got %+v", agentV, daemonV, r)
					}
					if r.Expected != contracts.ExpectedHandshakeRule {
						t.Fatalf("the refusal must name the expected rule %q, got %q", contracts.ExpectedHandshakeRule, r.Expected)
					}
					if r.Message == "" {
						t.Fatal("the refusal carries no human message")
					}
				}

				// Both outcomes survive the answer battery and the strict
				// decoder round-trip — the refusal's fields are wire
				// documents, not log text.
				if errs := contracts.ValidateHelloReply(rep); len(errs) != 0 {
					t.Fatalf("the negotiation answer refused by its own battery: %v", errs)
				}
				canonical, err := contracts.CanonicalHelloJSON(rep)
				if err != nil {
					t.Fatalf("canonical encode: %v", err)
				}
				decoded, err := contracts.DecodeHelloReply(canonical)
				if err != nil {
					t.Fatalf("the answer does not round-trip the strict decoder: %v", err)
				}
				recanonical, err := contracts.CanonicalHelloJSON(decoded)
				if err != nil {
					t.Fatalf("canonical re-encode: %v", err)
				}
				if string(recanonical) != string(canonical) {
					t.Fatalf("the decoded answer re-encodes differently:\n %s\n %s", canonical, recanonical)
				}
			})
		}
	}

	// The sub-1 rows are not matrix rows at all: a hello announcing
	// version 0 is refused by the shape battery before any negotiation.
	t.Run("version-zero hello is shape-invalid", func(t *testing.T) {
		if errs := contracts.ValidateHelloRequest(contracts.HelloRequest{ProtocolVersion: 0}); len(errs) == 0 {
			t.Fatal("a hello announcing protocol_version 0 was accepted; versions start at 1")
		}
	})

	// The refusal direction does not matter to the law: an OLDER agent
	// and a NEWER agent both refuse (the half-applied update can skew
	// either way), and each refusal names the stale side by version.
	t.Run("skew direction named both ways", func(t *testing.T) {
		newerDaemon := contracts.NegotiateHello(contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion}, contracts.ProtocolVersion+1)
		if newerDaemon.Refusal == nil || newerDaemon.Refusal.AgentProtocolVersion != contracts.ProtocolVersion || newerDaemon.Refusal.DaemonProtocolVersion != contracts.ProtocolVersion+1 {
			t.Fatalf("the older-agent refusal must name the stale agent: %+v", newerDaemon.Refusal)
		}
		olderDaemon := contracts.NegotiateHello(contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion + 1}, contracts.ProtocolVersion)
		if olderDaemon.Refusal == nil || olderDaemon.Refusal.AgentProtocolVersion != contracts.ProtocolVersion+1 || olderDaemon.Refusal.DaemonProtocolVersion != contracts.ProtocolVersion {
			t.Fatalf("the newer-agent refusal must name the stale daemon: %+v", olderDaemon.Refusal)
		}
	})
}

// TestRefusalVocabularyCompleteness pins the vocabulary's completeness:
// exactly the six names exist, each composes its named shape, each
// shape's golden document is on disk, and each document round-trips the
// strict decoder to a valid refusal. The test consumes the same
// goldenRefusalFixtures table as the golden pinning test, so the
// vocabulary, the constructors, and the fixture files cannot disagree.
// A seventh name — or a name whose golden document is missing — fails
// the battery, so the vocabulary can only grow through this test's
// deliberate update.
func TestRefusalVocabularyCompleteness(t *testing.T) {
	// The table IS the vocabulary: six names, each carrying its
	// constructor-composed shape. The count is pinned so the vocabulary
	// cannot grow silently.
	if len(goldenRefusalFixtures) != 6 {
		t.Fatalf("the vocabulary grew to %d names; the completeness pin, the golden fixtures, and the vocabulary's doc comment must grow with it deliberately", len(goldenRefusalFixtures))
	}

	for _, fx := range goldenRefusalFixtures {
		name, refusal := fx.name, fx.shape
		t.Run(name, func(t *testing.T) {
			if err := refusal.Validate(); err != nil {
				t.Fatalf("the %s shape refused by its own battery: %v", name, err)
			}

			// The golden document exists.
			path := filepath.Join("testdata", "golden", "middleman", name+".json")
			pinned, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("the vocabulary's golden document is missing for %s (%s); every named refusal is pinned as wire bytes", name, path)
			}

			// The golden document is the shape's canonical form and
			// round-trips the strict decoder.
			canonical, err := contracts.CanonicalMiddlemanJSON(refusal)
			if err != nil {
				t.Fatalf("canonical encode: %v", err)
			}
			if string(canonical) != string(pinned) {
				t.Fatalf("the golden document for %s drifted from the named shape:\n pinned: %s\n shape:  %s", name, pinned, canonical)
			}
			decoded, err := contracts.DecodeRefusal(pinned)
			if err != nil {
				t.Fatalf("the golden document for %s no longer decodes: %v", name, err)
			}
			if decoded != refusal {
				t.Fatalf("the golden document for %s decodes to a different shape: %+v", name, decoded)
			}
			recanonical, err := contracts.CanonicalMiddlemanJSON(decoded)
			if err != nil {
				t.Fatalf("canonical re-encode: %v", err)
			}
			if string(recanonical) != string(pinned) {
				t.Fatalf("the decoded %s document re-encodes differently:\n pinned: %s\n decoded: %s", name, pinned, recanonical)
			}
		})
	}

	// The names that are deliberately NOT vocabulary: the daemon's
	// journal-plus-close conventions (console-line-oversize,
	// digest-pin-mismatch, launch-binary-missing) name ALARM JOURNAL
	// lines for vocabulary-less failures — the daemon fires the alarm,
	// journals the cause, and closes the connection loudly. They are
	// not wire refusal names, and the battery refuses a wire document
	// that tries to carry one, so the alarm-line convention can never
	// silently become protocol vocabulary (growing the vocabulary is a
	// deliberate contracts version).
	t.Run("alarm-line conventions are not vocabulary", func(t *testing.T) {
		for _, alarmLine := range []string{"console-line-oversize", "digest-pin-mismatch", "launch-binary-missing"} {
			for _, fx := range goldenRefusalFixtures {
				if strings.EqualFold(string(fx.shape.Name), alarmLine) {
					t.Fatalf("%s became wire vocabulary without the battery's deliberate update", alarmLine)
				}
			}
			if err := (contracts.Refusal{Name: contracts.RefusalName(alarmLine), Message: "not a wire name"}).Validate(); err == nil {
				t.Fatalf("a refusal document carrying the alarm-line name %s was accepted; the vocabulary refuses it", alarmLine)
			}
		}
	})
}

// TestGoldenMaskedVersusRawConsolePair pins the console tap's masking
// stance from the golden line pair (the daemon seeds the same pair in
// its own tree; the battery pins the WIRE side of the stance): a
// registered secret planted in job output arrives masked — every served
// LogStream record declares masked=true and carries *** where the raw
// line carries the secret — and the raw form never appears in the
// mirrored capture. The daemon's part (d) record names the follow-up
// honestly: the pair is a fixture, not an observed live mask; a live
// masked capture from a real forge runner pins the stance again when
// one exists.
func TestGoldenMaskedVersusRawConsolePair(t *testing.T) {
	masked, err := os.ReadFile(filepath.Join("testdata", "golden", "middleman", "console-masked.log"))
	if err != nil {
		t.Fatalf("read the masked golden pair side: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "middleman", "console-raw.log"))
	if err != nil {
		t.Fatalf("read the raw golden pair side: %v", err)
	}

	maskedLines := strings.Split(strings.TrimSuffix(string(masked), "\n"), "\n")
	rawLines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(maskedLines) != len(rawLines) {
		t.Fatalf("masking preserves the line structure: %d masked vs %d raw lines", len(maskedLines), len(rawLines))
	}
	if len(maskedLines) < 3 {
		t.Fatalf("the golden pair carries too few lines to prove the stance: %d", len(maskedLines))
	}

	// Extract the secret spans: what each raw line carries where the
	// masked line shows *** (the shared prefix ends at the mask, the
	// shared suffix resumes after it).
	var secrets []string
	maskedLineCount := 0
	for i := range rawLines {
		if rawLines[i] == maskedLines[i] {
			continue // a line without a secret masks to itself
		}
		mask := strings.Index(maskedLines[i], "***")
		if mask < 0 {
			t.Fatalf("a differing line must carry the mask: %q", maskedLines[i])
		}
		prefix := maskedLines[i][:mask]
		suffix := maskedLines[i][mask+3:]
		at := strings.Index(rawLines[i], prefix)
		if at < 0 {
			t.Fatalf("the raw line must share the masked line's prefix: %q vs %q", rawLines[i], maskedLines[i])
		}
		secret := rawLines[i][at+len(prefix):]
		if suffix != "" {
			if cut := strings.LastIndex(secret, suffix); cut >= 0 {
				secret = secret[:cut]
			}
		}
		if secret == "" {
			t.Fatalf("the differing span must be non-empty: %q", rawLines[i])
		}
		secrets = append(secrets, secret)
		maskedLineCount++
	}
	if len(secrets) != 3 || maskedLineCount != 3 {
		t.Fatalf("the golden pair carries exactly three masked spans, got %d spans over %d masked lines: %v", len(secrets), maskedLineCount, secrets)
	}

	// The wire stance: every masked line serves as a LogStream record
	// with masked=true, inside a valid tap reply, and NO raw secret
	// substring appears anywhere in the mirrored capture.
	for i, line := range maskedLines {
		rec := contracts.LogStream{
			StreamID: "tap-golden",
			JobID:    "job-20261108-000009",
			Sequence: int64(i + 1),
			Masked:   true,
			Line:     line,
		}
		if errs := contracts.ValidateLogStream(rec); len(errs) != 0 {
			t.Fatalf("masked line %d refused by the wire battery: %v", i+1, errs)
		}
		reply := contracts.TapConsoleReply{
			Reply:  contracts.ReplyHeader{Op: contracts.OpTapConsole, OpID: "op-tap-golden", OK: true},
			Stream: &rec,
		}
		if errs := contracts.ValidateTapConsoleReply(reply); len(errs) != 0 {
			t.Fatalf("the masked line %d's tap reply refused: %v", i+1, errs)
		}
		canonical, err := contracts.CanonicalMiddlemanJSON(reply)
		if err != nil {
			t.Fatalf("canonical encode: %v", err)
		}
		if strings.Contains(string(canonical), "\n") {
			t.Fatalf("the canonical tap record carries a newline (the one-record-per-op wire law): %s", canonical)
		}

		// The unmasked twin is refused: the capture point is the masked
		// stream only.
		rawTwin := rec
		rawTwin.Masked = false
		if errs := contracts.ValidateLogStream(rawTwin); len(errs) == 0 {
			t.Fatalf("line %d: an unmasked record was accepted; the wire refuses it", i+1)
		}
	}

	// The mirrored capture (every masked line, joined as the tap would
	// mirror it) carries no raw secret.
	mirrored := strings.Join(maskedLines, "\n")
	for _, secret := range secrets {
		if strings.Contains(mirrored, secret) {
			t.Fatalf("the raw secret %q appears in the mirrored capture; the raw form never crosses", secret)
		}
	}
}
