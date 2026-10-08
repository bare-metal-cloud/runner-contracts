package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// CancelSpec is the signed cancel directive the control plane hands a
// runner: stop the named job attempt if (and only if) it is executing.
// It is the ONE wire schema for the build cancel verb (the freshness
// cancel picker's contract leg): the identity is the job-spec's own
// idempotency key (run reference, attempt) plus the job id, so a
// directive can only ever name an attempt the platform itself signed a
// spec for.
//
// The directive carries the same signature discipline as the job spec:
// canonical JSON bytes, a detached Ed25519 signature made with the SAME
// engine key that signs job specs, and a strict decoder that refuses any
// field the schema does not know. A machine that holds the engine verify
// key for job specs verifies cancel directives with it — no new trust
// anchor exists.
type CancelSpec struct {
	// JobID is the platform-generated job identifier whose executing
	// attempt the directive stops.
	JobID string `json:"job_id"`

	// RunReference names the pipeline run the job belongs to (the
	// job-spec's field, verbatim).
	RunReference string `json:"run_reference"`

	// Attempt is the 1-based attempt counter (the job-spec's field,
	// verbatim). Together with the run reference it is the attempt
	// identity; a directive whose attempt does not match the executing
	// one is refused by the executor.
	Attempt int `json:"attempt"`

	// Reason is the cancellation's named cause. The class is part of
	// the reason vocabulary (cancelled is the verb's own class); the
	// human message travels verbatim into the cancelled attempt's
	// terminal evidence.
	Reason Reason `json:"reason"`
}

// ValidateCancel runs the cancel directive's validation battery and
// returns every finding. An empty return means the directive is valid.
// The identity fields enforce the job-spec schema's own grammar (the
// same rules, the same bounds), and the reason runs the reason battery.
func ValidateCancel(c CancelSpec) ValidationErrors {
	var errs ValidationErrors

	if c.JobID == "" {
		errs = append(errs, required("job_id"))
	} else if len(c.JobID) > MaxJobIDLength || !jobIDRe.MatchString(c.JobID) {
		errs = append(errs, ValidationError{
			Field: "job_id",
			Rule:  RuleJobID,
			Message: fmt.Sprintf("job_id %q must be at most %d characters of letters, digits, dots, hyphens, and underscores, and must start with a letter or digit",
				c.JobID, MaxJobIDLength),
		})
	}
	if c.RunReference == "" {
		errs = append(errs, required("run_reference"))
	} else if len(c.RunReference) > MaxRunReferenceLength || containsWhitespace(c.RunReference) {
		errs = append(errs, ValidationError{
			Field: "run_reference",
			Rule:  RuleRunReference,
			Message: fmt.Sprintf("run_reference %q must be at most %d characters and carry no whitespace",
				c.RunReference, MaxRunReferenceLength),
		})
	}
	if c.Attempt < 1 {
		errs = append(errs, ValidationError{
			Field:   "attempt",
			Rule:    RuleAttempt,
			Message: fmt.Sprintf("attempt %d must be at least 1 (attempts are a 1-based counter)", c.Attempt),
		})
	}
	if err := c.Reason.Validate(); err != nil {
		// Reason.Validate returns the typed single-finding error; the
		// battery appends it to the findings list unchanged.
		if verr, ok := err.(ValidationError); ok {
			errs = append(errs, verr)
		} else {
			errs = append(errs, ValidationError{Field: "reason", Rule: RuleReasonClass, Message: err.Error()})
		}
	}
	// The message cap is the cancel battery's own: the directive's
	// message travels into the cancelled attempt's ledger row verbatim,
	// so its size is bounded here at signing and re-checked at
	// verification (ValidateCancel runs on both sides).
	if len(c.Reason.Message) > MaxReasonMessageLength {
		errs = append(errs, ValidationError{
			Field: "reason.message",
			Rule:  RuleReasonMessage,
			Message: fmt.Sprintf("reason message is %d characters, at most %d are allowed (the message rides the ledger's failure reason verbatim)",
				len(c.Reason.Message), MaxReasonMessageLength),
		})
	}
	return errs
}

// CanonicalCancelJSON returns the canonical JSON encoding of the
// directive: the exact byte form the cancel signatures are computed
// over. The determinism laws are CanonicalJSON's (schema declaration
// order, no insignificant whitespace, no HTML escaping).
func CanonicalCancelJSON(c CancelSpec) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	// json.Encoder appends exactly one newline; the canonical form has
	// no trailing whitespace.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SignCancel validates the directive against its battery and, only when
// it is valid, returns the detached Ed25519 signature over the
// directive's canonical JSON encoding. The discipline is Sign's
// (validate-then-act, deterministic RFC 8032 signatures), applied to the
// verb: a signed cancel directive is by construction a valid one.
func SignCancel(key ed25519.PrivateKey, c CancelSpec) ([]byte, error) {
	if errs := ValidateCancel(c); len(errs) != 0 {
		return nil, errs
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ValidationErrors{{
			Field:   "private_key",
			Rule:    RuleSignatureInvalid,
			Message: "private key is not an Ed25519 private key (wrong size)",
		}}
	}
	doc, err := CanonicalCancelJSON(c)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, doc), nil
}

// VerifyCancel checks a detached Ed25519 signature over a cancel
// directive. The discipline is Verify's: the document is size-bounded
// before any parsing, its bytes must be exactly the canonical encoding
// of their content, the signature must verify under the engine verify
// key, and — only after all that — the directive runs its validation
// battery. "VerifyCancel returned nil" is "this directive is canonical,
// authentic, and valid".
func VerifyCancel(pub ed25519.PublicKey, doc, sig []byte) error {
	if len(doc) > MaxDocumentBytes {
		return ValidationErrors{{
			Field: "document",
			Rule:  RuleDocumentSize,
			Message: fmt.Sprintf("document is %d bytes, at most %d are allowed (the %s rule bounds a document before any parsing)",
				len(doc), MaxDocumentBytes, RuleDocumentSize),
		}}
	}
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

	c, err := decodeCancelDocument(doc)
	if err != nil {
		return err
	}
	recanonical, err := CanonicalCancelJSON(c)
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

	// The validate-then-accept law: a valid signature never smuggles an
	// invalid directive past verification.
	if verrs := ValidateCancel(c); len(verrs) != 0 {
		return verrs
	}
	return nil
}

// decodeCancelDocument decodes a cancel directive without field
// strictness. It backs VerifyCancel's canonical re-encode check; the
// strict decode is DecodeCancelSpec.
func decodeCancelDocument(doc []byte) (CancelSpec, error) {
	var c CancelSpec
	if err := json.Unmarshal(doc, &c); err != nil {
		return CancelSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed cancel-directive JSON document: " + err.Error(),
		}}
	}
	return c, nil
}
