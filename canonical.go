package contracts

import (
	"bytes"
	"encoding/json"
)

// CanonicalJSON returns the canonical JSON encoding of spec: the exact
// byte form the signatures are computed over.
//
// The canonical form is deterministic by construction:
//
//   - struct fields serialize in schema declaration order,
//   - map keys serialize in sorted byte order,
//   - no insignificant whitespace,
//   - no HTML escaping.
//
// A nil EgressAllowlist or MeteringTags is normalized to an explicit
// empty list or object, so the deny-all choice is visible on the wire
// and nil-versus-empty never forks the canonical bytes.
//
// The encoding is stable across map insertion orders and JSON key
// orders of the source document (pinned by the canonical-stability
// tests): two consumers holding the same document always produce the
// same bytes, which is what makes detached signatures verifiable across
// independent consumers.
func CanonicalJSON(spec JobSpec) ([]byte, error) {
	if spec.EgressAllowlist == nil {
		spec.EgressAllowlist = []string{}
	}
	if spec.MeteringTags == nil {
		spec.MeteringTags = map[string]string{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(spec); err != nil {
		return nil, err
	}
	// json.Encoder appends exactly one newline; the canonical form has
	// no trailing whitespace.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
