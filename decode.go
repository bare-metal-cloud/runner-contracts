package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// DecodeJobSpec decodes a job-spec document strictly: the document must
// be well-formed JSON, and every field it carries must be part of the
// schema. An unknown field is refused by name (the unknown_field rule) —
// a consumer must never silently ignore a field it does not know, because
// the sender may have meant something the receiver would then drop.
//
// The decoder accepts keys in any order (wire compatibility is about
// content, not byte form); canonical byte form is only mandatory where
// signatures live, and Verify enforces it there.
//
// The returned error is a typed ValidationErrors (RuleMalformed or
// RuleUnknownField).
func DecodeJobSpec(doc []byte) (JobSpec, error) {
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

// decodeDocument decodes a job-spec document without field strictness. It
// backs Verify's canonical re-encode check: any content Verify cannot
// round-trip byte-identically is refused there as not_canonical, so a
// non-strict decode cannot smuggle anything past verification.
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
func unknownFieldName(err error) (string, bool) {
	const marker = `json: unknown field "`
	msg := err.Error()
	if !strings.HasPrefix(msg, marker) || !strings.HasSuffix(msg, `"`) {
		return "", false
	}
	return msg[len(marker) : len(msg)-1], true
}
