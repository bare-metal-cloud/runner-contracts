package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// loadTestEngineKey reads the pinned test seed from testdata. The key is
// TEST-ONLY material: it signs fixtures and exercises the API, and is
// never a real trust anchor.
func loadTestEngineKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "keys", "test-engine-seed.hex"))
	if err != nil {
		t.Fatalf("read test seed: %v", err)
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("test seed is not hex: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("test seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	spec := validFullSpec()
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := contracts.Verify(pub, doc, sig); err != nil {
		t.Fatalf("Verify refused a correctly signed document: %v", err)
	}
}

// TestTwoIndependentConsumersRoundTrip is the story's first AC: given a
// signed document, two independent consumers round-trip it through sign
// and verify, both accept it, and both decode identical content. Consumer
// A constructs and signs the spec. Consumer B starts from the wire bytes
// only: it verifies, decodes, and re-canonicalizes. The two must agree
// byte-for-byte.
func TestTwoIndependentConsumersRoundTrip(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	// Consumer A: the engine side. Signs the job spec.
	specA := validFullSpec()
	docA, err := contracts.CanonicalJSON(specA)
	if err != nil {
		t.Fatalf("consumer A canonicalize: %v", err)
	}
	sig, err := contracts.Sign(key, specA)
	if err != nil {
		t.Fatalf("consumer A sign: %v", err)
	}

	// Consumer B: the agent side. Receives only doc bytes and the
	// detached signature; verifies and decodes.
	if err := contracts.Verify(pub, docA, sig); err != nil {
		t.Fatalf("consumer B verify: %v", err)
	}
	specB, err := contracts.DecodeJobSpec(docA)
	if err != nil {
		t.Fatalf("consumer B decode: %v", err)
	}
	docB, err := contracts.CanonicalJSON(specB)
	if err != nil {
		t.Fatalf("consumer B canonicalize: %v", err)
	}
	sigB, err := contracts.Sign(key, specB)
	if err != nil {
		t.Fatalf("consumer B sign: %v", err)
	}

	if !bytes.Equal(docA, docB) {
		t.Fatal("the two consumers decoded different content (canonical forms differ)")
	}
	if !bytes.Equal(sig, sigB) {
		t.Fatal("the two consumers produced different signatures over identical content")
	}
}

func TestVerifyRefusesTamperedDocument(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	spec := validFullSpec()
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := bytes.Replace(doc, []byte("payments-ci"), []byte("payments-TH"), 1)
	if bytes.Equal(tampered, doc) {
		t.Fatal("test is broken: the tamper changed nothing")
	}
	err = contracts.Verify(pub, tampered, sig)
	if err == nil {
		t.Fatal("Verify accepted a tampered document")
	}
	// A same-length value substitution is still canonical JSON, so the
	// canonical re-encode check passes and the signature itself must
	// reject the tampered bytes.
	assertRule(t, err, contracts.RuleSignatureInvalid, "a tampered document must fail signature verification")
}

func TestVerifyRefusesWrongKey(t *testing.T) {
	key := loadTestEngineKey(t)
	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = byte(255 - i)
	}
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)

	spec := validFullSpec()
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := contracts.Verify(otherPub, doc, sig); err == nil {
		t.Fatal("Verify accepted a signature made by a different key")
	} else {
		assertRule(t, err, contracts.RuleSignatureInvalid, "wrong key must surface as signature_invalid")
	}
}

// TestVerifyRefusesNonCanonicalWireForm pins the strict canonical
// re-encode check: the signature is computed over the canonical encoding,
// and Verify refuses a wire document whose bytes are not that encoding,
// even when the JSON content is equivalent.
func TestVerifyRefusesNonCanonicalWireForm(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	spec := validFullSpec()
	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	canonical, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
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
	err = contracts.Verify(pub, reordered, sig)
	if err == nil {
		t.Fatal("Verify accepted a non-canonical wire form")
	}
	assertRule(t, err, contracts.RuleNotCanonical, "non-canonical wire form must be refused by name")
}

func TestSignatureDeterministic(t *testing.T) {
	key := loadTestEngineKey(t)
	spec := validFullSpec()
	sig1, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign 1: %v", err)
	}
	sig2, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign 2: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Ed25519 signing is deterministic (RFC 8032); two signatures over the same document differ")
	}
}

func TestSignRefusesInvalidSpec(t *testing.T) {
	key := loadTestEngineKey(t)
	spec := validMinimalSpec()
	spec.Image = "ghcr.io/acme/payments:latest" // mutable tag
	if _, err := contracts.Sign(key, spec); err == nil {
		t.Fatal("Sign accepted a spec that violates the digest-only law")
	} else {
		assertRule(t, err, contracts.RuleDigestOnly, "Sign must refuse to sign an invalid spec")
	}
}

func TestSignVerifyRejectBadKeyAndSignatureSizes(t *testing.T) {
	key := loadTestEngineKey(t)
	spec := validMinimalSpec()

	shortKey := ed25519.PrivateKey(make([]byte, 16))
	if _, err := contracts.Sign(shortKey, spec); err == nil {
		t.Fatal("Sign accepted a malformed private key")
	}

	pub := key.Public().(ed25519.PublicKey)
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if err := contracts.Verify(pub, doc, []byte("short")); err == nil {
		t.Fatal("Verify accepted a malformed signature length")
	}
	if err := contracts.Verify(ed25519.PublicKey(make([]byte, 8)), doc, make([]byte, ed25519.SignatureSize)); err == nil {
		t.Fatal("Verify accepted a malformed public key length")
	}
}

// TestDetachedSignatureBase64Transport documents the transport shape: the
// signature is detached raw bytes; consumers carry it base64-encoded.
func TestDetachedSignatureBase64Transport(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)
	spec := validMinimalSpec()
	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	encoded := base64.StdEncoding.EncodeToString(sig)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 round trip: %v", err)
	}
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if err := contracts.Verify(pub, doc, decoded); err != nil {
		t.Fatalf("Verify refused the base64-transported signature: %v", err)
	}
}

// assertRule asserts that err is ValidationErrors containing rule.
func assertRule(t *testing.T, err error, rule, context string) {
	t.Helper()
	errs, ok := err.(contracts.ValidationErrors)
	if !ok {
		t.Fatalf("%s: error is %T, want contracts.ValidationErrors", context, err)
	}
	for _, e := range errs {
		if e.Rule == rule {
			return
		}
	}
	t.Fatalf("%s: no error with rule=%s in %v", context, rule, errs)
}
