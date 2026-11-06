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
// be well-formed JSON and carry only fields the schema knows; each
// schema key must appear exactly once at every nesting level, and the
// top-level keys must match the schema exactly, case-sensitively.
// Concretely, the decoder refuses:
//
//   - a document larger than MaxDocumentBytes (the document_size rule,
//     checked before any parsing bounds the work a hostile document can
//     force),
//   - an unknown field, named, by the unknown_field rule. Top-level
//     keys are matched case-SENSITIVELY against the schema's exact tag
//     set: the stdlib's struct decode folds "JOB_ID" into job_id by its
//     case-insensitive match, and a case-variant key almost always means
//     the sender meant something the receiver would silently move,
//   - a duplicated key at ANY nesting level (the stdlib decode would
//     silently take the last occurrence).
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
// carry only fields the schema knows, carry each schema key exactly
// once at every nesting level, and stay inside MaxDocumentBytes (the
// duplicate-key refusal is a walk over the whole document — see
// DecodeJobSpec and checkDocumentKeys). The returned
// error is a typed ValidationErrors (RuleMalformed, RuleUnknownField, or
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

// checkDocumentKeys walks the document's object tree and refuses any
// key that breaks the document law. At the TOP level every key must be
// exactly a schema tag — case-sensitive, unknown refused. At EVERY
// level, top and nested, each key may appear at most once: the stdlib
// decode silently takes the last occurrence of a duplicate key at any
// depth, so the exactly-once refusal reaches below the top level too
// (before R2.13 the scan stopped at the top level, and a duplicate
// nested inside an object or an array element slipped through to the
// silent last-wins).
//
// Values are scanned, not interpreted: a nested UNKNOWN field stays the
// strict struct decode's refusal (DisallowUnknownFields names it), while
// a nested DUPLICATE key — which the struct decode would silently fold —
// is refused here. Arrays are walked, so an object inside an array
// carries the same law. The walk is bounded by MaxDocumentBytes, which
// the caller checks before any parsing.
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
	return scanObjectKeys(dec, fieldNames, what, "$", malformed)
}

// scanObjectKeys reads one JSON object body off dec (the opening brace
// is already consumed), applies the key law at this nesting level, and
// recurses into every value it passes. path names the scan's position
// for the refusal: "$" is the top level, "envelope" a nested object,
// "artifacts[]" an element of the artifacts array.
func scanObjectKeys(dec *json.Decoder, fieldNames map[string]bool, what, path string, malformed func(error) error) error {
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return malformed(err)
		}
		key, ok := tok.(string)
		if !ok {
			return malformed(fmt.Errorf("object key is not a string"))
		}
		if path == "$" && !fieldNames[key] {
			return ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries an unknown field %q; the schema refuses fields it does not know", key),
			}}
		}
		if seen[key] {
			where := ""
			if path != "$" {
				where = " inside " + path
			}
			return ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries the field %q more than once%s; a field may appear exactly once at every nesting level", key, where),
			}}
		}
		seen[key] = true
		if err := scanValueKeys(dec, fieldNames, what, path+"."+key, malformed); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // consume the closing brace
		return malformed(err)
	}
	return nil
}

// scanValueKeys consumes the value dec is positioned on and recurses
// into it when it is an object or an array — the levels the
// exactly-once key law reaches. Scalars are consumed and done.
//
// The walk streams tokens from the SAME decoder and never re-decodes a
// value into a fresh sub-decoder. (An earlier form decoded each value
// with dec.Decode(&raw) and re-scanned the copy, which re-copied the
// whole remaining value at every nesting level: quadratic — a ~1MB
// document nested 9,900 deep spent tens of seconds of CPU in
// DecodeJobSpec. The token walk reads each value's tokens once and
// decodes the same document in milliseconds.) Recursion depth is
// bounded by the stdlib scanner's own nesting cap: encoding/json
// refuses documents nested deeper than 10,000 levels as malformed
// ("exceeded max depth") before the walk can descend further, so the
// walk cannot recurse unboundedly on any document the decoder accepts.
func scanValueKeys(dec *json.Decoder, fieldNames map[string]bool, what, path string, malformed func(error) error) error {
	tok, err := dec.Token()
	if err != nil {
		return malformed(err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar: consumed, nothing further to scan
	}
	switch delim {
	case '{':
		return scanObjectKeys(dec, fieldNames, what, path, malformed)
	case '[':
		for dec.More() {
			if err := scanValueKeys(dec, fieldNames, what, path+"[]", malformed); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // consume the closing bracket
			return malformed(err)
		}
		return nil
	default:
		// '}' or ']' cannot begin a value: every caller sits where a
		// value may appear and those delimiters are consumed by the
		// readers above. Unreachable; refuse rather than silently pass.
		return malformed(fmt.Errorf("invalid character %q looking for beginning of value", delim))
	}
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
