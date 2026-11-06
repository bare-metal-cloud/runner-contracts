package contracts_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// The middleman protocol's validation battery. The wire is the
// contract; these tests pin the laws the batteries enforce — the
// deadline law (Health's short deadline among them), the custody law's
// decode-time refusal, the one-shot delivery retry shape, the typed
// refusal vocabulary, the handshake's exact-match law, and the strict
// decode's document law.

var middlemanBaseTime = time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)

// fixtureDigest is a well-formed bare sha256 pin for the fixtures (64
// lowercase hex characters).
const fixtureDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validFixtureDelivery() contracts.Delivery {
	return contracts.Delivery{
		DeliveryAttempt:        1,
		JobID:                  "job-20261106-000007",
		RunReference:           "acme/payments@main:run-420",
		Attempt:                1,
		Forge:                  contracts.ForgeGitHub,
		StartRender:            "#!/usr/bin/env bash\nset -euo pipefail\nexec systemd-run --unit=bmc-runner-420 /opt runner/bin/run.sh\n",
		FreshRegistrationToken: "fixture-registration-token-0001",
		DigestPin:              fixtureDigest,
		Artifacts: []contracts.DeliveryArtifact{
			{Name: "runner-binary", Reference: "rail://runners/github/2.321.0", Digest: fixtureDigest},
		},
	}
}

func TestValidateDeliveryBattery(t *testing.T) {
	if errs := contracts.ValidateDelivery(validFixtureDelivery()); len(errs) != 0 {
		t.Fatalf("valid delivery refused: %v", errs)
	}

	cases := []struct {
		name    string
		mutate  func(*contracts.Delivery)
		wantErr bool
	}{
		{"zero delivery attempt", func(d *contracts.Delivery) { d.DeliveryAttempt = 0 }, true},
		{"empty fresh token", func(d *contracts.Delivery) { d.FreshRegistrationToken = "" }, true},
		{"unknown forge", func(d *contracts.Delivery) { d.Forge = "circleci" }, true},
		{"empty start render", func(d *contracts.Delivery) { d.StartRender = "" }, true},
		{"unpinned digest", func(d *contracts.Delivery) { d.DigestPin = "sha256:short" }, true},
		{"mutable tag as pin", func(d *contracts.Delivery) { d.DigestPin = "latest" }, true},
		{"artifact with unpinned digest", func(d *contracts.Delivery) {
			d.Artifacts[0].Digest = "sha1:0123456789abcdef0123456789abcdef01234567"
		}, true},
		{"retry shape attempt two with fresh token", func(d *contracts.Delivery) {
			d.DeliveryAttempt = 2
			d.FreshRegistrationToken = "fixture-registration-token-0002"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validFixtureDelivery()
			tc.mutate(&d)
			errs := contracts.ValidateDelivery(d)
			if tc.wantErr && len(errs) == 0 {
				t.Fatalf("expected the battery to refuse the delivery, it accepted it")
			}
			if !tc.wantErr && len(errs) != 0 {
				t.Fatalf("expected the battery to accept the delivery, it refused: %v", errs)
			}
		})
	}
}

// TestCustodyLawWireRefusal proves the custody law's decode-time
// enforcement: the signing seed (and any other custody material) is not
// a field of the protocol's schema, so a document carrying one is
// refused by name — it cannot ride the wire even when the sender
// insists.
func TestCustodyLawWireRefusal(t *testing.T) {
	req := contracts.PrepareRequest{
		Envelope: contracts.Envelope{Op: contracts.OpPrepare, OpID: "op-0001", DeadlineUnixMs: middlemanBaseTime.Add(time.Minute).UnixMilli()},
		Delivery: validFixtureDelivery(),
	}
	canonical, err := contracts.CanonicalMiddlemanJSON(req)
	if err != nil {
		t.Fatalf("canonical encode: %v", err)
	}

	inject := func(t *testing.T, doc []byte, field, where string) []byte {
		t.Helper()
		var generic map[string]json.RawMessage
		if err := json.Unmarshal(doc, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if where == "top" {
			generic[field] = json.RawMessage(`"smuggled"`)
		} else {
			var delivery map[string]json.RawMessage
			if err := json.Unmarshal(generic["delivery"], &delivery); err != nil {
				t.Fatalf("unmarshal delivery: %v", err)
			}
			delivery[field] = json.RawMessage(`"smuggled"`)
			generic["delivery"], err = json.Marshal(delivery)
			if err != nil {
				t.Fatalf("marshal delivery: %v", err)
			}
		}
		out, err := json.Marshal(generic)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		field string
		where string
	}{
		{"completion signing seed at the top level", "completion_sign_seed", "top"},
		{"completion signing seed inside the delivery", "completion_sign_seed", "delivery"},
		{"build token inside the delivery", "build_token", "delivery"},
		{"registry password inside the delivery", "registry_password", "delivery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			smuggled := inject(t, canonical, tc.field, tc.where)
			_, err := contracts.DecodePrepareRequest(smuggled)
			if err == nil {
				t.Fatalf("the decoder accepted a document carrying %q; custody material must be refused by name", tc.field)
			}
			if !strings.Contains(err.Error(), "unknown_field") {
				t.Fatalf("the refusal is not the unknown_field rule: %v", err)
			}
		})
	}

	// The schema's own key set is the positive form of the same law:
	// reflect the Delivery struct's json tags and compare them to the
	// explicit allowed list, so a custody-material field cannot join
	// the schema silently.
	allowed := map[string]bool{
		"delivery_attempt": true, "job_id": true, "run_reference": true,
		"attempt": true, "forge": true, "start_render": true,
		"fresh_registration_token": true, "digest_pin": true, "artifacts": true,
	}
	typ := reflect.TypeFor[contracts.Delivery]()
	for i := 0; i < typ.NumField(); i++ {
		tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if !allowed[tag] {
			t.Fatalf("Delivery gained the field %q, which is not in the custody-safe allowlist; the custody law needs a deliberate, reviewed wire change", tag)
		}
		delete(allowed, tag)
	}
	if len(allowed) != 0 {
		t.Fatalf("the custody-safe allowlist names fields the schema lost: %v", allowed)
	}
}

func TestEnvelopeDeadlineLaw(t *testing.T) {
	now := middlemanBaseTime
	cases := []struct {
		name     string
		op       string
		span     time.Duration
		wantRule string
		wantOK   bool
	}{
		{"prepare inside the op bound", contracts.OpPrepare, 30 * time.Minute, "", true},
		{"prepare over the op bound", contracts.OpPrepare, 2 * time.Hour, "deadline", false},
		{"health at the short bound", contracts.OpHealth, contracts.MaxHealthDeadline, "", true},
		{"health over the short bound", contracts.OpHealth, 30 * time.Second, "health_deadline", false},
		{"already past", contracts.OpPrepare, -time.Second, "deadline", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := contracts.Envelope{Op: tc.op, OpID: "op-deadline-1", DeadlineUnixMs: now.Add(tc.span).UnixMilli()}
			errs := contracts.ValidateEnvelope(e, now)
			if tc.wantOK {
				if len(errs) != 0 {
					t.Fatalf("expected the envelope to be valid, it was refused: %v", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("expected the envelope to be refused, it was valid")
			}
			if !strings.Contains(errs[0].Rule, tc.wantRule) {
				t.Fatalf("expected the %s rule, got %s (%v)", tc.wantRule, errs[0].Rule, errs)
			}
		})
	}

	t.Run("unknown op name", func(t *testing.T) {
		e := contracts.Envelope{Op: "exec_shell", OpID: "op-x-1", DeadlineUnixMs: now.Add(time.Minute).UnixMilli()}
		errs := contracts.ValidateEnvelope(e, now)
		if len(errs) == 0 || errs[0].Rule != "op_name" {
			t.Fatalf("expected the op_name rule for an off-op-set request, got %v", errs)
		}
		if contracts.IsMiddlemanOp("exec_shell") {
			t.Fatal("exec_shell must not be an op-set name: the daemon's authority is scoped to exactly the six verbs")
		}
	})
}

// TestPrepareRetryShape pins the one-shot delivery retry shape: a retry
// is the same delivery identity with the attempt counter advanced and a
// FRESH token; there is no field that could carry a daemon-side token
// cache.
func TestPrepareRetryShape(t *testing.T) {
	now := middlemanBaseTime
	env := contracts.Envelope{Op: contracts.OpPrepare, OpID: "op-retry-1", DeadlineUnixMs: now.Add(time.Minute).UnixMilli()}

	first := contracts.PrepareRequest{Envelope: env, Delivery: validFixtureDelivery()}
	if errs := contracts.ValidatePrepareRequest(first, now); len(errs) != 0 {
		t.Fatalf("first delivery refused: %v", errs)
	}

	retry := first
	retry.Delivery = validFixtureDelivery()
	retry.Delivery.DeliveryAttempt = 2
	retry.Delivery.FreshRegistrationToken = "fixture-registration-token-0002"
	if errs := contracts.ValidatePrepareRequest(retry, now); len(errs) != 0 {
		t.Fatalf("fresh-token retry refused: %v", errs)
	}

	missing := first
	missing.Delivery = validFixtureDelivery()
	missing.Delivery.DeliveryAttempt = 2
	// The battery cannot judge token freshness (that is the agent's
	// duty at compose time), but the shape must make every attempt
	// carry the fresh-token field — the missing-field refusal is the
	// decode-level law.
	missing.Delivery.FreshRegistrationToken = ""
	if errs := contracts.ValidatePrepareRequest(missing, now); len(errs) == 0 {
		t.Fatal("a delivery without the fresh-token field was accepted; the retry shape requires it on every attempt")
	}
}

func TestRefusalVocabulary(t *testing.T) {
	shapes := []contracts.Refusal{
		contracts.RefusalBusyOp(contracts.OpPrepare),
		contracts.RefusalDeadline(),
		contracts.RefusalUnknownJobRef("job-20261106-000007"),
		contracts.RefusalUnknownTargetRef(contracts.CleanTargetStage, "/var/lib/runnermand/stages/op-0001"),
		contracts.RefusalDisplacedBy("agent-build-2241"),
		contracts.RefusalUnknownOpName("exec_shell"),
	}
	for _, r := range shapes {
		if err := r.Validate(); err != nil {
			t.Fatalf("refusal %s refused by its own battery: %v", r.Name, err)
		}
	}
	// The named shapes ride a reply header cleanly.
	header := contracts.ReplyHeader{Op: contracts.OpPrepare, OpID: "op-r-1", Refusal: &shapes[0]}
	if errs := contracts.ValidateReplyHeader(header); len(errs) != 0 {
		t.Fatalf("busy refusal in a reply header refused: %v", errs)
	}

	if err := (contracts.Refusal{Name: "made-up-refusal", Message: "x"}).Validate(); err == nil {
		t.Fatal("an off-vocabulary refusal name was accepted; the names are the contract")
	}
	if err := (contracts.Refusal{Name: contracts.RefusalBusy, Message: ""}).Validate(); err == nil {
		t.Fatal("a refusal without a human message was accepted")
	}

	// An accepted reply carries no refusal; a refused reply always
	// carries one.
	if errs := contracts.ValidateReplyHeader(contracts.ReplyHeader{Op: contracts.OpHealth, OpID: "op-r-2", OK: true, Refusal: &shapes[1]}); len(errs) == 0 {
		t.Fatal("an accepted reply carrying a refusal document was accepted")
	}
	if errs := contracts.ValidateReplyHeader(contracts.ReplyHeader{Op: contracts.OpHealth, OpID: "op-r-3"}); len(errs) == 0 {
		t.Fatal("a refused reply without a refusal document was accepted")
	}
}

func TestHandshakeExactMatch(t *testing.T) {
	agent := contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion, AgentBuild: "agent-build-2241"}

	accept := contracts.NegotiateHello(agent, contracts.ProtocolVersion)
	if !accept.Accepted || accept.ProtocolVersion != contracts.ProtocolVersion || accept.Refusal != nil {
		t.Fatalf("equal versions must accept cleanly, got %+v", accept)
	}
	if errs := contracts.ValidateHelloReply(accept); len(errs) != 0 {
		t.Fatalf("accepted reply refused: %v", errs)
	}

	refused := contracts.NegotiateHello(contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion + 1}, contracts.ProtocolVersion)
	if refused.Accepted || refused.Refusal == nil {
		t.Fatalf("a version skew must refuse with the refusal document, got %+v", refused)
	}
	r := refused.Refusal
	if r.AgentProtocolVersion != contracts.ProtocolVersion+1 || r.DaemonProtocolVersion != contracts.ProtocolVersion {
		t.Fatalf("the refusal must name BOTH versions, got %+v", r)
	}
	if r.Expected != contracts.ExpectedHandshakeRule || r.Message == "" {
		t.Fatalf("the refusal must name the expected rule and a human message, got %+v", r)
	}
	if errs := contracts.ValidateHelloReply(refused); len(errs) != 0 {
		t.Fatalf("refused reply refused by its own battery: %v", errs)
	}

	if errs := contracts.ValidateHelloReply(contracts.HelloReply{Accepted: false, ProtocolVersion: 1}); len(errs) == 0 {
		t.Fatal("a refusal without the refusal document was accepted; the loud-by-name law requires the document")
	}
	if errs := contracts.ValidateHelloReply(contracts.HelloReply{Accepted: true, ProtocolVersion: 1, Refusal: refused.Refusal}); len(errs) == 0 {
		t.Fatal("an acceptance carrying a refusal document was accepted")
	}
}

// TestTapAndCleanRefusalShapes pins the refusal-by-name shapes the
// runtime laws name: an unknown tap job and a foreign clean target.
func TestTapAndCleanRefusalShapes(t *testing.T) {
	now := middlemanBaseTime
	env := contracts.Envelope{Op: contracts.OpTapConsole, OpID: "op-tap-1", DeadlineUnixMs: now.Add(time.Minute).UnixMilli()}
	req := contracts.TapConsoleRequest{
		Envelope: env,
		Job:      contracts.JobRef{JobID: "job-20261106-000009", RunReference: "acme/web@main:run-99", Attempt: 1},
	}
	if errs := contracts.ValidateTapConsoleRequest(req, now); len(errs) != 0 {
		t.Fatalf("valid tap request refused: %v", errs)
	}

	unknown := contracts.TapConsoleReply{
		Reply:  contracts.ReplyHeader{Op: contracts.OpTapConsole, OpID: env.OpID, Refusal: refusalPtr(contracts.RefusalUnknownJobRef(req.Job.JobID))},
		Stream: nil,
	}
	if errs := contracts.ValidateTapConsoleReply(unknown); len(errs) != 0 {
		t.Fatalf("unknown-job refusal reply refused: %v", errs)
	}

	foreign := contracts.RunCleanCycleReply{
		Reply: contracts.ReplyHeader{Op: contracts.OpRunCleanCycle, OpID: "op-clean-1", Refusal: refusalPtr(contracts.RefusalUnknownTargetRef(contracts.CleanTargetPath, "/etc/passwd"))},
	}
	if errs := contracts.ValidateRunCleanCycleReply(foreign); len(errs) != 0 {
		t.Fatalf("unknown-target refusal reply refused: %v", errs)
	}
	if errs := contracts.ValidateCleanOp(contracts.CleanOp{Targets: []contracts.CleanTarget{{Kind: "arbitrary", Ref: "/etc"}}}); len(errs) == 0 {
		t.Fatal("a clean target off the kind vocabulary was accepted; the bounds law starts at the document")
	}
}

// TestMaskedStreamStance pins the masking stance's wire form: a tap
// record that declares itself unmasked is refused by the battery.
func TestMaskedStreamStance(t *testing.T) {
	good := contracts.LogStream{StreamID: "tap-0001", JobID: "job-20261106-000009", Sequence: 41, Masked: true, Line: "step 3 done **masked**"}
	if errs := contracts.ValidateLogStream(good); len(errs) != 0 {
		t.Fatalf("masked record refused: %v", errs)
	}
	raw := good
	raw.Masked = false
	if errs := contracts.ValidateLogStream(raw); len(errs) == 0 {
		t.Fatal("an unmasked tap record was accepted; the capture point is the masked stream only")
	}
}

func TestStrictDecodeLaws(t *testing.T) {
	now := middlemanBaseTime
	env := contracts.Envelope{Op: contracts.OpHealth, OpID: "op-dec-1", DeadlineUnixMs: now.Add(time.Second).UnixMilli()}
	doc, err := contracts.CanonicalMiddlemanJSON(contracts.HealthRequest{Envelope: env})
	if err != nil {
		t.Fatalf("canonical encode: %v", err)
	}

	if _, err := contracts.DecodeHealthRequest(doc); err != nil {
		t.Fatalf("valid document refused: %v", err)
	}
	if _, err := contracts.DecodeHealthRequest([]byte(`{"envelope":{},"extra":1}`)); err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("unknown top-level field not refused by name: %v", err)
	}
	dup := []byte(`{"envelope":{"op":"health","op_id":"a","deadline_unix_ms":1},"envelope":{"op":"health","op_id":"a","deadline_unix_ms":1}}`)
	if _, err := contracts.DecodeHealthRequest(dup); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicated key not refused: %v", err)
	}
	if _, err := contracts.DecodeHealthRequest(append(doc, []byte(" {}")...)); err == nil {
		t.Fatal("trailing content not refused")
	}
	if _, err := contracts.DecodeHealthRequest(make([]byte, contracts.MaxDocumentBytes+1)); err == nil || !strings.Contains(err.Error(), "document_size") {
		t.Fatalf("oversized document not refused by the size rule: %v", err)
	}

	// A reply decodes with the same law, and payload presence is the
	// reply battery's, not the decoder's.
	ok, err := contracts.DecodeTapConsoleReply([]byte(`{"reply":{"op":"tap_console","op_id":"a","ok":true},"stream":{"stream_id":"tap-1","job_id":"job-1","sequence":0,"masked":true,"line":"hi","eof":false}}`))
	if err != nil {
		t.Fatalf("valid tap reply refused: %v", err)
	}
	if errs := contracts.ValidateTapConsoleReply(ok); len(errs) != 0 {
		t.Fatalf("valid tap reply battery refused: %v", errs)
	}
}

// TestIdleReceiptIsLegal pins the clean cycle's idempotence-friendly
// shape: a cycle over already-scrubbed targets answers with a receipt
// that scrubs nothing.
func TestIdleReceiptIsLegal(t *testing.T) {
	r := contracts.Receipt{CycleID: "op-clean-1", Scrubbed: nil, AtUnixMs: middlemanBaseTime.UnixMilli()}
	if errs := contracts.ValidateReceipt(r); len(errs) != 0 {
		t.Fatalf("an empty receipt was refused; a re-run over a partial scrub must answer with the same receipt shape: %v", errs)
	}
}

func refusalPtr(r contracts.Refusal) *contracts.Refusal { return &r }
