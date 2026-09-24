package contracts

import (
	"bytes"
	"crypto/ed25519"
)

// Sign validates the spec against the schema's laws and, only when it is
// valid, returns the detached Ed25519 signature over the spec's canonical
// JSON encoding. The signature is deterministic (RFC 8032): two calls with
// the same key and the same spec produce identical bytes.
//
// Sign refuses to sign an invalid spec (a signed document is by
// construction a valid one), returning the typed ValidationErrors from
// the validation battery. A malformed private key is also refused; the
// stdlib's ed25519.Sign would panic on one.
func Sign(key ed25519.PrivateKey, spec JobSpec) ([]byte, error) {
	if errs := Validate(spec); len(errs) != 0 {
		return nil, errs
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ValidationErrors{{
			Field:   "private_key",
			Rule:    RuleSignatureInvalid,
			Message: "private key is not an Ed25519 private key (wrong size)",
		}}
	}
	doc, err := CanonicalJSON(spec)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, doc), nil
}

// Verify checks a detached Ed25519 signature over a job-spec document.
//
// Verification is strict about the wire form: the document's bytes must
// be exactly the canonical encoding of its content. Verify re-encodes the
// parsed document and refuses any byte drift with the not_canonical rule,
// so an equivalent-but-reordered JSON form (or one with extra fields)
// never verifies even with a valid signature. Only after the byte-form
// check passes is the signature itself verified.
//
// The returned error is a typed ValidationErrors naming the failing rule
// (RuleSignatureInvalid, RuleNotCanonical, or RuleMalformed).
func Verify(pub ed25519.PublicKey, doc, sig []byte) error {
	var errs ValidationErrors
	if len(pub) != ed25519.PublicKeySize {
		errs = append(errs, ValidationError{
			Field:   "public_key",
			Rule:    RuleSignatureInvalid,
			Message: "public key is not an Ed25519 public key (wrong size)",
		})
	}
	if len(sig) != ed25519.SignatureSize {
		errs = append(errs, ValidationError{
			Field:   "signature",
			Rule:    RuleSignatureInvalid,
			Message: "signature is not an Ed25519 signature (wrong size)",
		})
	}
	if len(errs) != 0 {
		return errs
	}

	// The canonical re-encode check: a document verifies only when its
	// bytes are the canonical encoding of its content. A plain decode
	// (not the strict one) is deliberate: any content-level oddity that
	// survives the decode shows up as a byte-form mismatch below.
	spec, err := decodeDocument(doc)
	if err != nil {
		return err
	}
	recanonical, err := CanonicalJSON(spec)
	if err != nil {
		return err
	}
	if !bytes.Equal(recanonical, doc) {
		return ValidationErrors{{
			Field:   "document",
			Rule:    RuleNotCanonical,
			Message: "document bytes are not the canonical encoding of their content; sign the canonical form",
		}}
	}

	if !ed25519.Verify(pub, doc, sig) {
		return ValidationErrors{{
			Field:   "signature",
			Rule:    RuleSignatureInvalid,
			Message: "signature does not verify over the document with this public key",
		}}
	}
	return nil
}
