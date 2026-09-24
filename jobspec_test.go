package contracts_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// GiB and TiB are byte counts used by the limit fixtures.
const (
	GiB = 1024 * 1024 * 1024
	TiB = 1024 * GiB
)

// sha256hex stretches a two-hex-character seed into a 64-character
// lowercase hex digest body for fixtures.
func sha256hex(seed string) string { return strings.Repeat(seed, 32) }

// imgRef builds a digest-only OCI reference for fixtures.
func imgRef(repo, seed string) string {
	return repo + "@sha256:" + sha256hex(seed)
}

func validMinimalSpec() contracts.JobSpec {
	command := []string{"make", "test"}
	return contracts.JobSpec{
		JobID:          "job-20260924-000001",
		RunReference:   "acme/payments@main:run-418",
		Attempt:        1,
		Image:          imgRef("ghcr.io/acme/payments", "ab"),
		Command:        command,
		TimeoutSeconds: 1800,
		Limits: contracts.ResourceLimits{
			CPUMillicores: 4000,
			MemoryBytes:   8 * GiB,
			DiskBytes:     64 * GiB,
		},
		EgressAllowlist: []string{},
		MeteringTags:    map[string]string{},
	}
}

func TestDecodeJobSpecAcceptsValidMinimal(t *testing.T) {
	doc, err := contracts.CanonicalJSON(validMinimalSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	spec, err := contracts.DecodeJobSpec(doc)
	if err != nil {
		t.Fatalf("DecodeJobSpec refused a valid minimal spec: %v", err)
	}
	if spec.JobID != "job-20260924-000001" {
		t.Errorf("JobID = %q, want %q", spec.JobID, "job-20260924-000001")
	}
}

func TestDecodeJobSpecStrictUnknownFieldRefusal(t *testing.T) {
	base, err := contracts.CanonicalJSON(validMinimalSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(base, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	generic["wat"] = 1
	doctored, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	_, err = contracts.DecodeJobSpec(doctored)
	if err == nil {
		t.Fatal("DecodeJobSpec accepted a document with an unknown field; want refusal")
	}
	errs, ok := err.(contracts.ValidationErrors)
	if !ok {
		t.Fatalf("error is %T, want contracts.ValidationErrors", err)
	}
	var found bool
	for _, e := range errs {
		if e.Rule == contracts.RuleUnknownField && strings.Contains(e.Message, "wat") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no unknown_field error naming the field \"wat\" in %v", errs)
	}
}

func TestDecodeJobSpecMalformedDocument(t *testing.T) {
	_, err := contracts.DecodeJobSpec([]byte("{not json"))
	if err == nil {
		t.Fatal("DecodeJobSpec accepted malformed JSON; want refusal")
	}
	errs, ok := err.(contracts.ValidationErrors)
	if !ok {
		t.Fatalf("error is %T, want contracts.ValidationErrors", err)
	}
	if len(errs) == 0 || errs[0].Rule != contracts.RuleMalformed {
		t.Fatalf("rule = %v, want %s", errs, contracts.RuleMalformed)
	}
}

// TestDecodeJobSpecRefusesCaseVariantField pins the exact-key law: the
// decoder matches schema keys case-SENSITIVELY, so "JOB_ID" is an unknown
// field even though encoding/json's struct decode would happily fold it
// into job_id by its case-insensitive match. A case-variant key almost
// always means the sender meant something the receiver would silently
// move.
func TestDecodeJobSpecRefusesCaseVariantField(t *testing.T) {
	base, err := contracts.CanonicalJSON(validMinimalSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(base, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	generic["JOB_ID"] = "job-20260924-999999"
	doctored, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	_, err = contracts.DecodeJobSpec(doctored)
	if err == nil {
		t.Fatal("DecodeJobSpec accepted a case-variant schema key; want refusal")
	}
	assertUnknownFieldNames(t, err, "JOB_ID")
}

// TestDecodeJobSpecRefusesDuplicateKeys pins the duplicate-key law: a
// document carrying the same schema field twice (under the exact same
// key, or under a case-variant sibling of it) is refused, never silently
// last-value-wins.
func TestDecodeJobSpecRefusesDuplicateKeys(t *testing.T) {
	t.Run("duplicate job_id and JOB_ID", func(t *testing.T) {
		base, err := contracts.CanonicalJSON(validMinimalSpec())
		if err != nil {
			t.Fatalf("CanonicalJSON: %v", err)
		}
		var generic map[string]any
		if err := json.Unmarshal(base, &generic); err != nil {
			t.Fatalf("fixture is not JSON: %v", err)
		}
		generic["JOB_ID"] = "job-20260924-999999"
		doctored, err := json.Marshal(generic)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		_, err = contracts.DecodeJobSpec(doctored)
		if err == nil {
			t.Fatal("DecodeJobSpec accepted job_id alongside its case-variant JOB_ID; want refusal")
		}
		assertUnknownFieldNames(t, err, "JOB_ID")
	})
	t.Run("exact duplicate job_id", func(t *testing.T) {
		raw := []byte(`{"job_id":"job-a","job_id":"job-b"}`)
		_, err := contracts.DecodeJobSpec(raw)
		if err == nil {
			t.Fatal("DecodeJobSpec accepted a duplicated job_id; want refusal")
		}
		assertUnknownFieldNames(t, err, "job_id")
	})
}

// TestDecodeJobSpecRefusesOversizedDocument pins the whole-document size
// guard: a document larger than MaxDocumentBytes is refused by name
// before any parsing, bounding the work a hostile document can force.
func TestDecodeJobSpecRefusesOversizedDocument(t *testing.T) {
	base, err := contracts.CanonicalJSON(validMinimalSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(base, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	generic["wat"] = strings.Repeat("a", contracts.MaxDocumentBytes)
	doctored, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if len(doctored) <= contracts.MaxDocumentBytes {
		t.Fatal("test is broken: the doctored document does not exceed the size cap")
	}

	_, err = contracts.DecodeJobSpec(doctored)
	if err == nil {
		t.Fatal("DecodeJobSpec accepted an oversized document; want refusal")
	}
	errs, ok := err.(contracts.ValidationErrors)
	if !ok {
		t.Fatalf("error is %T, want contracts.ValidationErrors", err)
	}
	var found bool
	for _, e := range errs {
		if e.Rule == contracts.RuleDocumentSize && strings.Contains(e.Message, fmt.Sprintf("%d", contracts.MaxDocumentBytes)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no document_size error naming the cap in %v", errs)
	}
}

// assertUnknownFieldNames asserts that err is a ValidationErrors carrying
// an unknown_field finding whose message names field.
func assertUnknownFieldNames(t *testing.T, err error, field string) {
	t.Helper()
	errs, ok := err.(contracts.ValidationErrors)
	if !ok {
		t.Fatalf("error is %T, want contracts.ValidationErrors", err)
	}
	for _, e := range errs {
		if e.Rule == contracts.RuleUnknownField && strings.Contains(e.Message, field) {
			return
		}
	}
	t.Fatalf("no unknown_field error naming %q in %v", field, errs)
}

func TestIdempotencyKeyComposition(t *testing.T) {
	spec := validMinimalSpec()
	key := spec.IdempotencyKey()
	if key.RunReference != spec.RunReference || key.Attempt != spec.Attempt {
		t.Fatalf("IdempotencyKey = %+v, want (run_reference=%q attempt=%d)",
			key, spec.RunReference, spec.Attempt)
	}
	// Two specs for the same run and attempt carry the same idempotency
	// key; a different attempt carries a different one.
	other := validMinimalSpec()
	if other.IdempotencyKey() != key {
		t.Fatal("identical (run_reference, attempt) pairs produced different idempotency keys")
	}
	other.Attempt = key.Attempt + 1
	if other.IdempotencyKey() == key {
		t.Fatal("a different attempt produced the same idempotency key")
	}
}

func TestCanonicalJSONStableAcrossMapInsertionOrders(t *testing.T) {
	build := func(order []string) contracts.JobSpec {
		spec := validMinimalSpec()
		tags := make(map[string]string)
		for _, k := range order {
			tags[k] = "v-" + k
		}
		spec.MeteringTags = tags
		return spec
	}
	forward := build([]string{"alpha", "beta", "gamma", "delta", "epsilon"})
	reverse := build([]string{"epsilon", "delta", "gamma", "beta", "alpha"})

	a, err := contracts.CanonicalJSON(forward)
	if err != nil {
		t.Fatalf("CanonicalJSON(forward): %v", err)
	}
	b, err := contracts.CanonicalJSON(reverse)
	if err != nil {
		t.Fatalf("CanonicalJSON(reverse): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical encoding depends on map insertion order:\n forward: %s\n reverse: %s", a, b)
	}
}

func TestCanonicalJSONStableAcrossJSONKeyOrders(t *testing.T) {
	ordered, err := contracts.CanonicalJSON(validFullSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// Re-encode through a generic map: encoding/json sorts map keys, so
	// the byte form differs from the struct-order canonical form while
	// carrying identical content.
	var generic map[string]any
	if err := json.Unmarshal(ordered, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if bytes.Equal(ordered, reordered) {
		t.Fatal("test is broken: the two wire forms are byte-identical, so nothing is proven")
	}

	spec, err := contracts.DecodeJobSpec(reordered)
	if err != nil {
		t.Fatalf("DecodeJobSpec refused the reordered document: %v", err)
	}
	canonical, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !bytes.Equal(canonical, ordered) {
		t.Fatalf("canonical re-encoding differs after key reorder:\n ordered:   %s\n reordered: %s", ordered, canonical)
	}
}

func TestCanonicalJSONIsCompactWithSortedMapKeys(t *testing.T) {
	doc, err := contracts.CanonicalJSON(validFullSpec())
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if bytes.ContainsAny(doc, " \t\n\r") {
		t.Fatalf("canonical encoding contains whitespace: %s", doc)
	}
	var generic map[string]any
	if err := json.Unmarshal(doc, &generic); err != nil {
		t.Fatalf("canonical form is not JSON: %v", err)
	}
	tags, err := json.Marshal(generic["metering_tags"])
	if err != nil {
		t.Fatalf("re-marshal tags: %v", err)
	}
	want := `{"org":"acme","pipeline":"payments-ci","project":"payments"}`
	if string(tags) != want {
		t.Fatalf("metering_tags not in sorted-key compact form: got %s, want %s", tags, want)
	}
}

func TestEnvEntryWireForms(t *testing.T) {
	plain := "count=1"
	secret := "credential-store://payments/ci/database-url"
	spec := validFullSpec()
	spec.Env = []contracts.EnvEntry{
		{Name: "GOFLAGS", Value: &plain},
		{Name: "DATABASE_URL", SecretReference: &secret},
	}
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	decoded, err := contracts.DecodeJobSpec(doc)
	if err != nil {
		t.Fatalf("DecodeJobSpec: %v", err)
	}
	if !reflect.DeepEqual(spec.Env, decoded.Env) {
		t.Fatalf("env entries did not round-trip:\n want %+v\n got  %+v", spec.Env, decoded.Env)
	}

	// An empty plain value is a legal value, not an absent one, and must
	// survive the round trip as a value (never degrade into "neither").
	empty := ""
	spec.Env = []contracts.EnvEntry{{Name: "CI_SILENT", Value: &empty}}
	doc, err = contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	decoded, err = contracts.DecodeJobSpec(doc)
	if err != nil {
		t.Fatalf("DecodeJobSpec refused an empty plain value: %v", err)
	}
	if decoded.Env[0].Value == nil || *decoded.Env[0].Value != "" {
		t.Fatalf("empty plain value degraded: %+v", decoded.Env[0])
	}
}
