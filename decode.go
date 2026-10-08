package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// DecodeJobSpec decodes a job-spec document strictly. The document must
// be well-formed JSON, carry only fields the schema knows, and carry
// each known field at most once. Concretely, the decoder refuses:
//
//   - a document larger than MaxDocumentBytes (the document_size rule,
//     checked before any parsing bounds the work a hostile document can
//     force),
//   - an unknown field, named, by the unknown_field rule. Keys are
//     matched case-SENSITIVELY against the schema's exact tag set: the
//     stdlib's struct decode folds "JOB_ID" into job_id by its
//     case-insensitive match, and a case-variant key almost always means
//     the sender meant something the receiver would silently move,
//   - a duplicated key (the stdlib decode would silently take the last
//     occurrence).
//
// The decoder accepts keys in any order (wire compatibility is about
// content, not byte form); canonical byte form is only mandatory where
// signatures live, and Verify enforces it there.
//
// The returned error is a typed ValidationErrors (RuleMalformed,
// RuleUnknownField, or RuleDocumentSize).
func DecodeJobSpec(doc []byte) (JobSpec, error) {
	if len(doc) > MaxDocumentBytes {
		return JobSpec{}, ValidationErrors{{
			Field: "document",
			Rule:  RuleDocumentSize,
			Message: fmt.Sprintf("document is %d bytes, at most %d are allowed (the %s rule bounds a document before any parsing)",
				len(doc), MaxDocumentBytes, RuleDocumentSize),
		}}
	}
	if err := checkDocumentKeys(doc, jobSpecFieldNames, "job-spec"); err != nil {
		return JobSpec{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var spec JobSpec
	if err := dec.Decode(&spec); err != nil {
		if name, ok := unknownFieldName(err); ok {
			return JobSpec{}, ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries an unknown field %q; the schema refuses fields it does not know", name),
			}}
		}
		return JobSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed job-spec JSON document: " + err.Error(),
		}}
	}
	// Nothing but whitespace may follow the JSON value.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return JobSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document carries trailing content after the JSON value",
		}}
	}
	return spec, nil
}

// DecodeCancelSpec decodes a cancel-directive document strictly, with
// DecodeJobSpec's exact law: the document must be well-formed JSON,
// carry only fields the schema knows, carry each known field at most
// once, and stay inside MaxDocumentBytes. The returned error is a typed
// ValidationErrors (RuleMalformed, RuleUnknownField, or
// RuleDocumentSize).
func DecodeCancelSpec(doc []byte) (CancelSpec, error) {
	if len(doc) > MaxDocumentBytes {
		return CancelSpec{}, ValidationErrors{{
			Field: "document",
			Rule:  RuleDocumentSize,
			Message: fmt.Sprintf("document is %d bytes, at most %d are allowed (the %s rule bounds a document before any parsing)",
				len(doc), MaxDocumentBytes, RuleDocumentSize),
		}}
	}
	if err := checkDocumentKeys(doc, cancelSpecFieldNames, "cancel-directive"); err != nil {
		return CancelSpec{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var c CancelSpec
	if err := dec.Decode(&c); err != nil {
		if name, ok := unknownFieldName(err); ok {
			return CancelSpec{}, ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries an unknown field %q; the schema refuses fields it does not know", name),
			}}
		}
		return CancelSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed cancel-directive JSON document: " + err.Error(),
		}}
	}
	// Nothing but whitespace may follow the JSON value.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return CancelSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document carries trailing content after the JSON value",
		}}
	}
	return c, nil
}

// jobSpecFieldNames is the exact set of top-level schema keys, derived
// from the JobSpec struct's json tags at init so it cannot drift from
// the schema.
var jobSpecFieldNames = schemaFieldNames(reflect.TypeFor[JobSpec]())

// cancelSpecFieldNames is the cancel directive's exact set of top-level
// schema keys, derived the same way.
var cancelSpecFieldNames = schemaFieldNames(reflect.TypeFor[CancelSpec]())

// schemaFieldNames derives a schema's exact json-tag key set from the
// struct type.
func schemaFieldNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool)
	for i := 0; i < t.NumField(); i++ {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		names[tag] = true
	}
	return names
}

// checkDocumentKeys scans the top level of doc as a JSON object and
// refuses any key that is not exactly a schema tag (case-sensitive), or
// that appears more than once. Values are skipped, not parsed: content
// validation is the validation battery's job; this pass only guards the
// key set the strict struct decode would otherwise handle too loosely
// (case-insensitive matches, silent last-wins duplicates).
func checkDocumentKeys(doc []byte, fieldNames map[string]bool, what string) error {
	malformed := func(err error) error {
		return ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed " + what + " JSON document: " + err.Error(),
		}}
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	tok, err := dec.Token()
	if err != nil {
		return malformed(err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return malformed(fmt.Errorf("document is not a JSON object"))
	}
	seen := make(map[string]bool, len(fieldNames))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return malformed(err)
		}
		key, ok := tok.(string)
		if !ok {
			return malformed(fmt.Errorf("object key is not a string"))
		}
		if !fieldNames[key] {
			return ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries an unknown field %q; the schema refuses fields it does not know", key),
			}}
		}
		if seen[key] {
			return ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries the field %q more than once; a field may appear exactly once", key),
			}}
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return malformed(err)
		}
	}
	if _, err := dec.Token(); err != nil { // consume the closing brace
		return malformed(err)
	}
	return nil
}

// decodeDocument decodes a job-spec document without field strictness. It
// backs Verify's canonical re-encode check: any content Verify cannot
// round-trip byte-identically is refused there as not_canonical, so a
// non-strict decode cannot smuggle anything past verification. Verify
// runs the full validation battery after the signature check, so the
// loose decode here never decides acceptance on its own.
func decodeDocument(doc []byte) (JobSpec, error) {
	var spec JobSpec
	if err := json.Unmarshal(doc, &spec); err != nil {
		return JobSpec{}, ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed job-spec JSON document: " + err.Error(),
		}}
	}
	return spec, nil
}

// unknownFieldName reports whether err is the stdlib decoder's
// unknown-field error, and extracts the field name it names.
//
// It matches on the stdlib's error STRING, not a typed error: as of Go
// 1.27, encoding/json exports no error type for unknown fields, so the
// message prefix is the only handle there is. This is the module's one
// stdlib error-string dependency; it is pinned by
// TestDecodeJobSpecStrictUnknownFieldRefusal (a nested unknown field —
// which the top-level key scan does not cover — must still surface as
// the unknown_field rule). If the stdlib ever grows a typed error,
// switch to it and drop this.
func unknownFieldName(err error) (string, bool) {
	const marker = `json: unknown field "`
	msg := err.Error()
	if !strings.HasPrefix(msg, marker) || !strings.HasSuffix(msg, `"`) {
		return "", false
	}
	return msg[len(marker) : len(msg)-1], true
}
