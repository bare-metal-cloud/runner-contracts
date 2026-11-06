package contracts

import (
	"fmt"
	"reflect"
)

// The connect-time version handshake. The agent announces the protocol
// version it was built against, the daemon answers with the version it
// implements, and an incompatible pair REFUSES LOUDLY BY NAME — the
// refusal document names both versions and the expected rule, so an
// operator sees exactly which side is stale.
//
// v1 compatibility is EXACT-MATCH-ONLY: a handshake admits equal
// versions; there is no compatible-range negotiation in v1. A range
// scheme would be a future version's change, admitted only through the
// same compat battery.
//
// In practice the pair never skews — both sides update together via the
// agent-release train — and the handshake is the backstop for the cases
// where they didn't (a half-applied update, a hand-poked binary).

// HelloRequest is the agent's connect-time announcement.
type HelloRequest struct {
	// ProtocolVersion is the protocol version the agent was built
	// against (the contracts module's ProtocolVersion constant).
	ProtocolVersion int `json:"protocol_version"`

	// AgentBuild is informational: the agent's build identity, for
	// the refusal message and the daemon's logs.
	AgentBuild string `json:"agent_build,omitempty"`
}

// HelloReply is the daemon's connect-time answer in both outcomes.
// ProtocolVersion is ALWAYS the daemon's implemented version — accepted
// or refused — and Refusal is present exactly when Accepted is false.
type HelloReply struct {
	Accepted        bool              `json:"accepted"`
	ProtocolVersion int               `json:"protocol_version"`
	Refusal         *HandshakeRefusal `json:"refusal,omitempty"`
}

// HandshakeRefusal is the loud refusal document: both versions named,
// plus the expected rule in operator-readable form. The update-quiesce
// law's agent behavior reads exactly these fields — a handshake refusal
// after an update marks the machine UNHEALTHY (release the slice, stop
// claiming, alarm, retry the update), never a quiet log line.
type HandshakeRefusal struct {
	AgentProtocolVersion  int    `json:"agent_protocol_version"`
	DaemonProtocolVersion int    `json:"daemon_protocol_version"`
	Expected              string `json:"expected"`
	Message               string `json:"message"`
}

// ExpectedHandshakeRule is the expected-pair rule the refusal names.
const ExpectedHandshakeRule = "agent_protocol_version == daemon_protocol_version (protocol v1 is exact-match-only: no compatible-range negotiation)"

// NegotiateHello applies the exact-match law and composes the reply:
// equal versions accept (the daemon echoes its version), any other pair
// refuses with both versions named. Both sides run this — the daemon
// on its socket, the agent to sanity-check the answer it got.
func NegotiateHello(hello HelloRequest, daemonVersion int) HelloReply {
	if hello.ProtocolVersion == daemonVersion {
		return HelloReply{Accepted: true, ProtocolVersion: daemonVersion}
	}
	return HelloReply{
		Accepted:        false,
		ProtocolVersion: daemonVersion,
		Refusal: &HandshakeRefusal{
			AgentProtocolVersion:  hello.ProtocolVersion,
			DaemonProtocolVersion: daemonVersion,
			Expected:              ExpectedHandshakeRule,
			Message: fmt.Sprintf("protocol versions differ: the agent announces %d, the daemon implements %d; update the stale side before any op flows",
				hello.ProtocolVersion, daemonVersion),
		},
	}
}

// ValidateHelloRequest checks the announcement's shape.
func ValidateHelloRequest(h HelloRequest) ValidationErrors {
	var errs ValidationErrors
	if h.ProtocolVersion < 1 {
		errs = append(errs, ValidationError{Field: "protocol_version", Rule: RuleProtocolVersion, Message: "protocol_version must be at least 1"})
	}
	if len(h.AgentBuild) > MaxReasonMessageLength {
		errs = append(errs, ValidationError{Field: "agent_build", Rule: RuleReasonMessage, Message: "agent_build exceeds the human-text bound"})
	}
	return errs
}

// ValidateHelloReply checks the answer's shape: the version must be
// present, and the refusal must be present exactly when the answer is
// a refusal — and a refusal document must name both versions.
func ValidateHelloReply(r HelloReply) ValidationErrors {
	var errs ValidationErrors
	if r.ProtocolVersion < 1 {
		errs = append(errs, ValidationError{Field: "protocol_version", Rule: RuleProtocolVersion, Message: "protocol_version must be at least 1"})
	}
	if !r.Accepted && r.Refusal == nil {
		errs = append(errs, ValidationError{Field: "refusal", Rule: RuleProtocolVersion, Message: "a refused handshake carries the refusal document (both versions named)"})
	}
	if r.Accepted && r.Refusal != nil {
		errs = append(errs, ValidationError{Field: "refusal", Rule: RuleProtocolVersion, Message: "an accepted handshake carries no refusal document"})
	}
	if r.Refusal != nil {
		if r.Refusal.AgentProtocolVersion < 1 || r.Refusal.DaemonProtocolVersion < 1 {
			errs = append(errs, ValidationError{Field: "refusal", Rule: RuleProtocolVersion, Message: "the refusal document names both versions; each must be at least 1"})
		}
		if r.Refusal.Expected == "" {
			errs = append(errs, required("refusal.expected"))
		}
		if r.Refusal.Message == "" {
			errs = append(errs, required("refusal.message"))
		}
	}
	return errs
}

// CanonicalHelloJSON returns the canonical JSON encoding of a hello
// document (request or reply): the middleman docs' byte form, with the
// determinism laws of CanonicalMiddlemanJSON.
func CanonicalHelloJSON(doc any) ([]byte, error) {
	return CanonicalMiddlemanJSON(doc)
}

// DecodeHelloRequest decodes a hello announcement strictly.
func DecodeHelloRequest(doc []byte) (HelloRequest, error) {
	var h HelloRequest
	if err := decodeMiddlemanDocument(doc, helloRequestFieldNames, "hello-request", &h); err != nil {
		return HelloRequest{}, err
	}
	return h, nil
}

// DecodeHelloReply decodes a hello answer strictly.
func DecodeHelloReply(doc []byte) (HelloReply, error) {
	var r HelloReply
	if err := decodeMiddlemanDocument(doc, helloReplyFieldNames, "hello-reply", &r); err != nil {
		return HelloReply{}, err
	}
	return r, nil
}

// helloRequestFieldNames and helloReplyFieldNames are the handshake
// documents' exact top-level key sets, derived from the struct tags at
// init so they cannot drift.
var (
	helloRequestFieldNames = schemaFieldNames(reflect.TypeFor[HelloRequest]())
	helloReplyFieldNames   = schemaFieldNames(reflect.TypeFor[HelloReply]())
)
