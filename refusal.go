package contracts

import (
	"fmt"
	"reflect"
)

// RefusalName is the typed refusal vocabulary of the machine-side
// middleman protocol. Every refusal on the socket is a wire document
// of this vocabulary — never a free-form error string improvised at
// the call site. The names are the contract: the agent's retry, backoff,
// and unhealthy-marking behavior matches on them.
type RefusalName string

// The refusal names.
//
//	busy                  — a machine-state-mutating op (Prepare,
//	                      RunCleanCycle) is already in flight; the
//	                      concurrent one is refused, not queued (the
//	                      op-serialization law: the caller owns retry
//	                      and backoff)
//	deadline-exceeded     — the op envelope's deadline passed before
//	                      the daemon could answer (the deadline law:
//	                      answer by name, never hang the agent)
//	unknown-job           — the TapConsole reference names no job the
//	                      daemon knows (refused by name, never hangs)
//	unknown-target        — a RunCleanCycle target the daemon's own
//	                      ledger does not name (the clean-op bounds
//	                      law: the receipts are the allowlist)
//	controller-displaced  — the displacement notice: a second controller
//	                      connection connected, and this side is the
//	                      one being dropped (the newcomer wins, so a
//	                      restarted agent can never wedge the daemon
//	                      behind a half-dead socket)
//	unknown-op            — a request whose op is not in the op set
//	                      (the daemon's authority is scoped to exactly
//	                      the six verbs)
//
// This list is the whole vocabulary. The daemon's runnermand carries
// failure conventions that are deliberately NOT wire names here:
// console-line-oversize, digest-pin-mismatch, and launch-binary-missing
// are the daemon's ALARM JOURNAL lines — the journal-plus-close
// convention for failures the vocabulary has no name for. The daemon
// fires the alarm, journals the cause, and closes the connection
// loudly; the agent's retry law owns the aftermath. Naming one of them
// in a wire refusal document is refused by the refusal battery, so the
// alarm-line convention can never silently become protocol vocabulary —
// growing this list is a deliberate contracts version (the digest-pin
// verify-failed refusal is the known candidate, deferred until a
// version admits it).
const (
	RefusalBusy                RefusalName = "busy"
	RefusalDeadlineExceeded    RefusalName = "deadline-exceeded"
	RefusalUnknownJob          RefusalName = "unknown-job"
	RefusalUnknownTarget       RefusalName = "unknown-target"
	RefusalControllerDisplaced RefusalName = "controller-displaced"
	RefusalUnknownOp           RefusalName = "unknown-op"
)

func isRefusalName(n RefusalName) bool {
	switch n {
	case RefusalBusy, RefusalDeadlineExceeded, RefusalUnknownJob,
		RefusalUnknownTarget, RefusalControllerDisplaced, RefusalUnknownOp:
		return true
	}
	return false
}

// Refusal is the typed refusal document: the named cause and a human
// message, with Detail carrying the refusal's named shape's optional
// payload (the op in flight for busy, the displaced side's successor
// identity for controller-displaced). The message is required — every
// refusal carries a human explanation wherever it travels.
type Refusal struct {
	Name    RefusalName `json:"name"`
	Message string      `json:"message"`
	Detail  string      `json:"detail,omitempty"`
}

// Validate checks the refusal's shape: the name must be part of the
// vocabulary and the human message must be present.
func (r Refusal) Validate() error {
	if r.Name == "" {
		return ValidationError{Field: "refusal.name", Rule: RuleRefusalName, Message: "refusal name is required"}
	}
	if !isRefusalName(r.Name) {
		return ValidationError{Field: "refusal.name", Rule: RuleRefusalName, Message: "unknown refusal name " + string(r.Name)}
	}
	if r.Message == "" {
		return ValidationError{Field: "refusal.message", Rule: RuleRefusalMessage, Message: "every refusal carries a human message"}
	}
	if len(r.Message) > MaxReasonMessageLength {
		return ValidationError{Field: "refusal.message", Rule: RuleRefusalMessage, Message: fmt.Sprintf("refusal message is %d characters, at most %d are allowed", len(r.Message), MaxReasonMessageLength)}
	}
	if len(r.Detail) > MaxReasonMessageLength {
		return ValidationError{Field: "refusal.detail", Rule: RuleRefusalMessage, Message: "refusal detail exceeds the human-text bound"}
	}
	return nil
}

// refusalFieldNames is the refusal document's exact top-level key set,
// derived from the struct tags at init so it cannot drift.
var refusalFieldNames = schemaFieldNames(reflect.TypeFor[Refusal]())

// DecodeRefusal decodes a refusal document strictly (the module's
// document law: size-bounded, known fields only, each at most once,
// nothing trailing).
func DecodeRefusal(doc []byte) (Refusal, error) {
	var r Refusal
	if err := decodeMiddlemanDocument(doc, refusalFieldNames, "refusal", &r); err != nil {
		return Refusal{}, err
	}
	return r, nil
}

// RefusalBusyOp composes the busy refusal for the op named in flight
// (the op-serialization law's named shape).
func RefusalBusyOp(op string) Refusal {
	return Refusal{
		Name:    RefusalBusy,
		Message: "a machine-state-mutating op is already in flight; concurrent mutating ops are refused, not queued",
		Detail:  op,
	}
}

// RefusalDeadline composes the deadline-exceeded refusal (the deadline
// law's named shape).
func RefusalDeadline() Refusal {
	return Refusal{
		Name:    RefusalDeadlineExceeded,
		Message: "the op envelope's deadline passed before the daemon could answer",
	}
}

// RefusalUnknownJobRef composes the unknown-job refusal for a tap
// reference the daemon does not know.
func RefusalUnknownJobRef(jobID string) Refusal {
	return Refusal{
		Name:    RefusalUnknownJob,
		Message: "the tap reference names no job this daemon knows",
		Detail:  jobID,
	}
}

// RefusalUnknownTargetRef composes the unknown-target refusal for a
// clean target the daemon's ledger does not name.
func RefusalUnknownTargetRef(kind, ref string) Refusal {
	return Refusal{
		Name:    RefusalUnknownTarget,
		Message: "the clean target is not in this daemon's ledger; the receipts, not the request, are the allowlist",
		Detail:  kind + " " + ref,
	}
}

// RefusalDisplacedBy composes the controller-displacement notice for
// the successor identity that displaced this connection.
func RefusalDisplacedBy(successor string) Refusal {
	return Refusal{
		Name:    RefusalControllerDisplaced,
		Message: "a second controller connection connected; the newcomer wins and this connection is dropped",
		Detail:  successor,
	}
}

// RefusalUnknownOpName composes the unknown-op refusal (the op-set
// scoping law's named shape).
func RefusalUnknownOpName(op string) Refusal {
	return Refusal{
		Name:    RefusalUnknownOp,
		Message: "the request's op is not in the protocol's op set; the daemon's authority is scoped to exactly the six verbs",
		Detail:  op,
	}
}
