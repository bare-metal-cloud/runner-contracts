package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// validCancelSpec is the fully-populated valid cancel directive used by
// the battery mutations and the golden fixture.
func validCancelSpec() contracts.CancelSpec {
	return contracts.CancelSpec{
		JobID:        "bld-9f1c2a3e-4b5d-4e6f-8a9b-0c1d2e3f4a5b",
		RunReference: "acme/payments@main:build-run-418",
		Attempt:      2,
		Reason: contracts.Reason{
			Class:   contracts.ReasonCancelled,
			Message: "cancel requested by org acme (user@example.com) from the deploys ledger",
		},
	}
}

// TestCancelVerbJoinsTheReasonVocabulary pins the cancel reason code's
// wire value and its disposition: a customer cancellation is the user's
// own stop — the engine never falls back to Tier P for it, it is never a
// platform fault, and it is never rendered as a customer failure.
func TestCancelVerbJoinsTheReasonVocabulary(t *testing.T) {
	if contracts.ReasonCancelled != "cancelled" {
		t.Fatalf("cancel reason wire value is %q, want %q", contracts.ReasonCancelled, "cancelled")
	}
	got, ok := contracts.DispositionFor(contracts.ReasonCancelled)
	if !ok {
		t.Fatal("the cancelled class has no disposition; the class-to-disposition map must cover every class")
	}
	if got != contracts.DispositionCancelled {
		t.Fatalf("DispositionFor(cancelled) = %q, want %q", got, contracts.DispositionCancelled)
	}
	if err := (contracts.Reason{Class: contracts.ReasonCancelled, Message: "stopped by request"}).Validate(); err != nil {
		t.Fatalf("the cancelled class was refused by Reason.Validate: %v", err)
	}
}

// TestCancelSpecValidationBattery is the cancel verb's validation law:
// the directive names a job attempt with the same identity grammar the
// job-spec schema enforces, and its reason carries a vocabulary class
// plus a human message.
func TestCancelSpecValidationBattery(t *testing.T) {
	if errs := contracts.ValidateCancel(validCancelSpec()); len(errs) != 0 {
		t.Fatalf("valid cancel directive refused: %v", errs)
	}

	mutations := map[string]func(*contracts.CancelSpec){
		"empty job_id":         func(c *contracts.CancelSpec) { c.JobID = "" },
		"bad job_id grammar":   func(c *contracts.CancelSpec) { c.JobID = "-nope" },
		"empty run_reference":  func(c *contracts.CancelSpec) { c.RunReference = "" },
		"whitespace run ref":   func(c *contracts.CancelSpec) { c.RunReference = "acme/payments@main: run-418" },
		"attempt zero":         func(c *contracts.CancelSpec) { c.Attempt = 0 },
		"empty reason class":   func(c *contracts.CancelSpec) { c.Reason.Class = "" },
		"unknown reason class": func(c *contracts.CancelSpec) { c.Reason.Class = "mystery" },
		"empty reason message": func(c *contracts.CancelSpec) { c.Reason.Message = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			spec := validCancelSpec()
			mutate(&spec)
			if errs := contracts.ValidateCancel(spec); len(errs) == 0 {
				t.Fatalf("%s: the battery accepted an invalid cancel directive", name)
			}
		})
	}
}

// TestSignCancelRoundTrip: the engine signs the directive, the machine
// verifies it, and both decode identical content — the job-spec's
// two-consumer law, applied to the cancel verb.
func TestSignCancelRoundTrip(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	doc, err := contracts.CanonicalCancelJSON(validCancelSpec())
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	sig, err := contracts.SignCancel(key, validCancelSpec())
	if err != nil {
		t.Fatalf("SignCancel: %v", err)
	}
	if err := contracts.VerifyCancel(pub, doc, sig); err != nil {
		t.Fatalf("VerifyCancel refused a correctly signed directive: %v", err)
	}
	decoded, err := contracts.DecodeCancelSpec(doc)
	if err != nil {
		t.Fatalf("DecodeCancelSpec: %v", err)
	}
	recanonical, err := contracts.CanonicalCancelJSON(decoded)
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	if !bytes.Equal(recanonical, doc) {
		t.Fatalf("decoded directive re-encodes differently:\n doc: %s\n decoded: %s", doc, recanonical)
	}
}

func TestSignCancelRefusesInvalidDirective(t *testing.T) {
	key := loadTestEngineKey(t)
	spec := validCancelSpec()
	spec.Attempt = 0 // the battery refuses attempt 0
	if _, err := contracts.SignCancel(key, spec); err == nil {
		t.Fatal("SignCancel signed an invalid directive; a signed document is by construction a valid one")
	}
}

func TestVerifyCancelRefusesTamperedDocument(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	doc, err := contracts.CanonicalCancelJSON(validCancelSpec())
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	sig, err := contracts.SignCancel(key, validCancelSpec())
	if err != nil {
		t.Fatalf("SignCancel: %v", err)
	}
	tampered := bytes.Replace(doc, []byte("build-run-418"), []byte("build-run-419"), 1)
	if bytes.Equal(tampered, doc) {
		t.Fatal("test is broken: the tamper changed nothing")
	}
	err = contracts.VerifyCancel(pub, tampered, sig)
	if err == nil {
		t.Fatal("VerifyCancel accepted a tampered directive")
	}
	assertRule(t, err, contracts.RuleSignatureInvalid, "a tampered directive must fail signature verification")
}

func TestVerifyCancelRefusesWrongKey(t *testing.T) {
	key := loadTestEngineKey(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = byte(200 - i)
	}
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)

	doc, err := contracts.CanonicalCancelJSON(validCancelSpec())
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	sig, err := contracts.SignCancel(key, validCancelSpec())
	if err != nil {
		t.Fatalf("SignCancel: %v", err)
	}
	if err := contracts.VerifyCancel(otherPub, doc, sig); err == nil {
		t.Fatal("VerifyCancel accepted a signature made by a different key")
	} else {
		assertRule(t, err, contracts.RuleSignatureInvalid, "wrong key must surface as signature_invalid")
	}
}

// TestVerifyCancelRefusesValidSignatureOverInvalidDirective pins the
// validate-then-accept law for the verb: a canonical document with a
// valid signature is STILL refused when the directive it carries
// violates the battery — SignCancel's refusal must not be the only gate.
func TestVerifyCancelRefusesValidSignatureOverInvalidDirective(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	spec := validCancelSpec()
	spec.Reason.Class = "mystery"
	doc, err := contracts.CanonicalCancelJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	sig := ed25519.Sign(key, doc) // raw signature, bypassing SignCancel
	err = contracts.VerifyCancel(pub, doc, sig)
	if err == nil {
		t.Fatal("VerifyCancel accepted a correctly signed but invalid directive")
	}
	assertRule(t, err, contracts.RuleReasonClass, "VerifyCancel must run the battery after the signature check")
}

// TestVerifyCancelRefusesNonCanonicalWireForm: the verb signs canonical
// bytes only, exactly like the job spec.
func TestVerifyCancelRefusesNonCanonicalWireForm(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	spec := validCancelSpec()
	sig, err := contracts.SignCancel(key, spec)
	if err != nil {
		t.Fatalf("SignCancel: %v", err)
	}
	canonical, err := contracts.CanonicalCancelJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(canonical, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if bytes.Equal(reordered, canonical) {
		t.Fatal("test is broken: the two wire forms are byte-identical, so nothing is proven")
	}
	if err := contracts.VerifyCancel(pub, reordered, sig); err == nil {
		t.Fatal("VerifyCancel accepted a non-canonical wire form")
	} else {
		assertRule(t, err, contracts.RuleNotCanonical, "non-canonical wire form must be refused by name")
	}
}

// TestDecodeCancelSpecStrict is the verb's decode law: unknown fields,
// duplicated keys, case-variant keys, and trailing content are refused by
// name; reordered keys decode fine (content is the contract, not byte
// form — canonical form is only mandatory where signatures live).
func TestDecodeCancelSpecStrict(t *testing.T) {
	doc, err := contracts.CanonicalCancelJSON(validCancelSpec())
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}

	refusals := map[string][]byte{
		"unknown field":     append(bytes.Clone(doc[:len(doc)-1]), []byte(`,"cancel_all":true}`)...),
		"duplicated key":    []byte(`{"job_id":"a","job_id":"a","run_reference":"r","attempt":1,"reason":{"class":"cancelled","message":"x"}}`),
		"case-variant key":  []byte(`{"JOB_ID":"a","run_reference":"r","attempt":1,"reason":{"class":"cancelled","message":"x"}}`),
		"trailing content":  append(bytes.Clone(doc), []byte(` {}`)...),
		"not an object":     []byte(`["nope"]`),
		"reason not object": []byte(`{"job_id":"a","run_reference":"r","attempt":1,"reason":"cancelled"}`),
	}
	for name, bad := range refusals {
		t.Run(name, func(t *testing.T) {
			if _, err := contracts.DecodeCancelSpec(bad); err == nil {
				t.Fatalf("%s: the decoder accepted the document", name)
			}
		})
	}

	// Reordered keys decode to identical content.
	var generic map[string]any
	if err := json.Unmarshal(doc, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	decoded, err := contracts.DecodeCancelSpec(reordered)
	if err != nil {
		t.Fatalf("reordered directive refused: %v", err)
	}
	recanonical, err := contracts.CanonicalCancelJSON(decoded)
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	if !bytes.Equal(recanonical, doc) {
		t.Fatalf("reordered directive decoded to different content:\n doc: %s\n decoded: %s", doc, recanonical)
	}
}

// TestCancelSpecWireGolden pins the verb's exact canonical field set and
// order: the wire values are the contract, and a field added or removed
// without a deliberate fixture update fails here.
func TestCancelSpecWireGolden(t *testing.T) {
	doc, err := contracts.CanonicalCancelJSON(validCancelSpec())
	if err != nil {
		t.Fatalf("CanonicalCancelJSON: %v", err)
	}
	const want = `{"job_id":"bld-9f1c2a3e-4b5d-4e6f-8a9b-0c1d2e3f4a5b",` +
		`"run_reference":"acme/payments@main:build-run-418","attempt":2,` +
		`"reason":{"class":"cancelled","message":"cancel requested by org acme (user@example.com) from the deploys ledger"}}`
	if string(doc) != want {
		t.Fatalf("cancel verb wire form drifted\n got: %s\nwant: %s", doc, want)
	}
}
