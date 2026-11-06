package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
)

// The request/reply envelope wire shapes for the machine-side
// middleman protocol's six ops. Every op is one request document and
// one reply document; every request carries the Envelope — the op
// name, the op's idempotency key, and the op's deadline. Every reply
// carries the ReplyHeader — the echoed identity and, on refusal, the
// typed refusal document (refusal.go). An op that succeeded carries
// its payload; an op that was refused carries no payload.
//
// The daemon enforces the deadline and answers deadline-exceeded by
// name rather than hanging the agent. Health's deadline is SHORT — the
// liveness-probe expectation is a named constant (MaxHealthDeadline)
// enforced by ValidateEnvelope, not a comment.

// The deadline law's constants. MaxHealthDeadline is the liveness
// probe's short deadline: a Health that cannot answer this fast is an
// unhealthy machine, not a slow one. MaxOpDeadline is the sanity bound
// any single op's deadline may carry (admission sanity, not a product
// limit — the daemon enforces its own per-op budgets on top).
const (
	MaxHealthDeadline = 5 * time.Second
	MaxOpDeadline     = time.Hour
)

// Envelope is every op request's common header.
type Envelope struct {
	// Op is the op-set name the request answers to (one of the Op*
	// constants).
	Op string `json:"op"`

	// OpID is the op's idempotency key: the identity a replay
	// carries, the key Prepare recognizes its own half-state by, and
	// the cycle id a RunCleanCycle receipt echoes.
	OpID string `json:"op_id"`

	// DeadlineUnixMs is the op's deadline: an absolute epoch-
	// milliseconds timestamp the daemon enforces. For Health it must
	// be no later than now + MaxHealthDeadline.
	DeadlineUnixMs int64 `json:"deadline_unix_ms"`
}

// ValidateEnvelope checks the envelope's shape against the deadline
// law, at compose time with now supplied. The op must be in the op
// set, the op id must carry the op-id grammar, and the deadline must
// be in the future, inside MaxOpDeadline, and — for Health — inside
// MaxHealthDeadline.
func ValidateEnvelope(e Envelope, now time.Time) ValidationErrors {
	var errs ValidationErrors
	if !IsMiddlemanOp(e.Op) {
		errs = append(errs, ValidationError{Field: "envelope.op", Rule: RuleOpName, Message: "envelope op must be one of the protocol's six op names"})
	}
	if e.OpID == "" {
		errs = append(errs, required("envelope.op_id"))
	} else if len(e.OpID) > MaxOpIDLength || !jobIDRe.MatchString(e.OpID) {
		errs = append(errs, ValidationError{Field: "envelope.op_id", Rule: RuleOpID, Message: "op_id must be at most 128 characters of letters, digits, dots, hyphens, and underscores, starting with a letter or digit"})
	}
	if e.DeadlineUnixMs <= 0 {
		errs = append(errs, ValidationError{Field: "envelope.deadline_unix_ms", Rule: RuleDeadline, Message: "deadline_unix_ms must be a positive epoch-milliseconds timestamp"})
		return errs
	}
	deadline := time.UnixMilli(e.DeadlineUnixMs)
	nowMs := now.UnixMilli()
	if e.DeadlineUnixMs <= nowMs {
		errs = append(errs, ValidationError{Field: "envelope.deadline_unix_ms", Rule: RuleDeadline, Message: "the deadline is already past at compose time"})
		return errs
	}
	span := deadline.Sub(now)
	if span > MaxOpDeadline {
		errs = append(errs, ValidationError{Field: "envelope.deadline_unix_ms", Rule: RuleDeadline, Message: fmt.Sprintf("the deadline spans %s, at most %s are allowed", span, MaxOpDeadline)})
	}
	if e.Op == OpHealth && span > MaxHealthDeadline {
		errs = append(errs, ValidationError{Field: "envelope.deadline_unix_ms", Rule: RuleHealthDeadline, Message: fmt.Sprintf("a Health deadline must be short — at most %s from now (a Health that cannot answer quickly is an unhealthy machine, not a slow one); this one spans %s", MaxHealthDeadline, span)})
	}
	return errs
}

// ReplyHeader is every op reply's common header. The echoed Op and
// OpID let the agent correlate a replay's answers. A refused reply
// carries the typed refusal document and no payload; an accepted reply
// carries Refusal nil.
type ReplyHeader struct {
	Op      string   `json:"op"`
	OpID    string   `json:"op_id"`
	OK      bool     `json:"ok"`
	Refusal *Refusal `json:"refusal,omitempty"`
}

// ValidateReplyHeader checks the header's shape.
func ValidateReplyHeader(h ReplyHeader) ValidationErrors {
	var errs ValidationErrors
	if !IsMiddlemanOp(h.Op) {
		errs = append(errs, ValidationError{Field: "reply.op", Rule: RuleOpName, Message: "reply op must be one of the protocol's six op names"})
	}
	if h.OpID == "" {
		errs = append(errs, required("reply.op_id"))
	} else if len(h.OpID) > MaxOpIDLength || !jobIDRe.MatchString(h.OpID) {
		errs = append(errs, ValidationError{Field: "reply.op_id", Rule: RuleOpID, Message: "op_id must carry the op-id grammar"})
	}
	if h.OK && h.Refusal != nil {
		errs = append(errs, ValidationError{Field: "reply.refusal", Rule: RuleRefusalShape, Message: "an accepted reply carries no refusal document"})
	}
	if !h.OK && h.Refusal == nil {
		errs = append(errs, ValidationError{Field: "reply.refusal", Rule: RuleRefusalShape, Message: "a refused reply carries the typed refusal document, never a free-form error string"})
	}
	if h.Refusal != nil {
		if err := h.Refusal.Validate(); err != nil {
			if verr, ok := err.(ValidationError); ok {
				errs = append(errs, verr)
			} else {
				errs = append(errs, ValidationError{Field: "reply.refusal", Rule: RuleRefusalShape, Message: err.Error()})
			}
		}
	}
	return errs
}

// The six ops' request documents. Each embeds the Envelope plus the
// op's own payload field (empty for the parameterless reads).

type PrepareRequest struct {
	Envelope Envelope `json:"envelope"`
	Delivery Delivery `json:"delivery"`
}

type MachineFactsRequest struct {
	Envelope Envelope `json:"envelope"`
}

type RunCleanCycleRequest struct {
	Envelope Envelope `json:"envelope"`
	Clean    CleanOp  `json:"clean"`
}

type HealthRequest struct {
	Envelope Envelope `json:"envelope"`
}

type SampleMetricsRequest struct {
	Envelope Envelope      `json:"envelope"`
	Window   MetricsWindow `json:"window"`
}

type TapConsoleRequest struct {
	Envelope Envelope `json:"envelope"`
	Job      JobRef   `json:"job"`
}

// The six ops' reply documents. The payload pointer is nil exactly when
// the reply header refused.

type PrepareReply struct {
	Reply  ReplyHeader   `json:"reply"`
	Handle *RunnerHandle `json:"handle,omitempty"`
}

type MachineFactsReply struct {
	Reply ReplyHeader `json:"reply"`
	Facts *Facts      `json:"facts,omitempty"`
}

type RunCleanCycleReply struct {
	Reply   ReplyHeader `json:"reply"`
	Receipt *Receipt    `json:"receipt,omitempty"`
}

type HealthReply struct {
	Reply  ReplyHeader   `json:"reply"`
	Health *HealthReport `json:"health,omitempty"`
}

type SampleMetricsReply struct {
	Reply   ReplyHeader    `json:"reply"`
	Metrics *RunnerMetrics `json:"metrics,omitempty"`
}

type TapConsoleReply struct {
	Reply  ReplyHeader `json:"reply"`
	Stream *LogStream  `json:"stream,omitempty"`
}

// The per-request validation batteries. Each checks the envelope
// against the deadline law (with now supplied) and the op's payload
// against its own battery.

func ValidatePrepareRequest(r PrepareRequest, now time.Time) ValidationErrors {
	errs := ValidateEnvelope(r.Envelope, now)
	errs = append(errs, ValidateDelivery(r.Delivery)...)
	return errs
}

func ValidateMachineFactsRequest(r MachineFactsRequest, now time.Time) ValidationErrors {
	return ValidateEnvelope(r.Envelope, now)
}

func ValidateRunCleanCycleRequest(r RunCleanCycleRequest, now time.Time) ValidationErrors {
	errs := ValidateEnvelope(r.Envelope, now)
	errs = append(errs, ValidateCleanOp(r.Clean)...)
	return errs
}

func ValidateHealthRequest(r HealthRequest, now time.Time) ValidationErrors {
	return ValidateEnvelope(r.Envelope, now)
}

func ValidateSampleMetricsRequest(r SampleMetricsRequest, now time.Time) ValidationErrors {
	errs := ValidateEnvelope(r.Envelope, now)
	errs = append(errs, ValidateMetricsWindow(r.Window)...)
	return errs
}

func ValidateTapConsoleRequest(r TapConsoleRequest, now time.Time) ValidationErrors {
	errs := ValidateEnvelope(r.Envelope, now)
	errs = append(errs, ValidateJobRef(r.Job)...)
	return errs
}

// The per-reply validation batteries: the header plus, when accepted,
// the payload battery and the refused-replies-carry-no-payload law.

func ValidatePrepareReply(r PrepareReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Handle != nil, func() ValidationErrors {
		return ValidateRunnerHandle(*r.Handle)
	})
}

func ValidateMachineFactsReply(r MachineFactsReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Facts != nil, func() ValidationErrors {
		return ValidateFacts(*r.Facts)
	})
}

func ValidateRunCleanCycleReply(r RunCleanCycleReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Receipt != nil, func() ValidationErrors {
		return ValidateReceipt(*r.Receipt)
	})
}

func ValidateHealthReply(r HealthReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Health != nil, func() ValidationErrors {
		return ValidateHealthReport(*r.Health)
	})
}

func ValidateSampleMetricsReply(r SampleMetricsReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Metrics != nil, func() ValidationErrors {
		return ValidateRunnerMetrics(*r.Metrics)
	})
}

func ValidateTapConsoleReply(r TapConsoleReply) ValidationErrors {
	return validateOpReply(r.Reply, r.Stream != nil, func() ValidationErrors {
		return ValidateLogStream(*r.Stream)
	})
}

// validateOpReply applies the shared reply law: the header battery,
// an accepted reply carries the payload, a refused reply carries none,
// and the payload runs its own battery.
func validateOpReply(h ReplyHeader, hasPayload bool, payload func() ValidationErrors) ValidationErrors {
	errs := ValidateReplyHeader(h)
	if h.OK && !hasPayload {
		errs = append(errs, ValidationError{Field: "reply", Rule: RuleRefusalShape, Message: "an accepted reply carries the op's payload"})
	}
	if !h.OK && hasPayload {
		errs = append(errs, ValidationError{Field: "reply", Rule: RuleRefusalShape, Message: "a refused reply carries no payload"})
	}
	if h.OK && hasPayload {
		errs = append(errs, payload()...)
	}
	return errs
}

// CanonicalMiddlemanJSON returns the canonical JSON encoding of any
// middleman wire document (request, reply, refusal, or handshake):
// struct fields in schema declaration order, no insignificant
// whitespace, no HTML escaping. The canonical form is what the golden
// fixtures pin; socket documents are authenticated by the socket
// security law (peer credentials), not by signatures, so the canonical
// form's role here is determinism and byte-stable compat pinning.
func CanonicalMiddlemanJSON(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	// json.Encoder appends exactly one newline; the canonical form has
	// no trailing whitespace.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// The strict decoders, one per wire document. Each applies the module's
// document law: size-bounded before any parsing, only fields the schema
// knows (named by the unknown_field rule; at the document's top level
// the keys are matched case-sensitively and each must appear exactly
// once), well-formed JSON, and nothing trailing the value. A document
// carrying an unknown field — which is how custody material such as a
// signing seed would have to ride the wire — is refused by name.
//
// The case-sensitive, exactly-once key refusal is a TOP-level
// guarantee. Inside a nested document (a delivery inside a
// prepare-request, an artifact inside the delivery) duplicate or
// case-variant keys are not scanned: they fall through to
// encoding/json's usual case-insensitive, last-occurrence-wins decode.

func DecodePrepareRequest(doc []byte) (PrepareRequest, error) {
	var r PrepareRequest
	err := decodeMiddlemanDocument(doc, prepareRequestFieldNames, "prepare-request", &r)
	return r, err
}

func DecodePrepareReply(doc []byte) (PrepareReply, error) {
	var r PrepareReply
	err := decodeMiddlemanDocument(doc, prepareReplyFieldNames, "prepare-reply", &r)
	return r, err
}

func DecodeMachineFactsRequest(doc []byte) (MachineFactsRequest, error) {
	var r MachineFactsRequest
	err := decodeMiddlemanDocument(doc, machineFactsRequestFieldNames, "machine-facts-request", &r)
	return r, err
}

func DecodeMachineFactsReply(doc []byte) (MachineFactsReply, error) {
	var r MachineFactsReply
	err := decodeMiddlemanDocument(doc, machineFactsReplyFieldNames, "machine-facts-reply", &r)
	return r, err
}

func DecodeRunCleanCycleRequest(doc []byte) (RunCleanCycleRequest, error) {
	var r RunCleanCycleRequest
	err := decodeMiddlemanDocument(doc, runCleanCycleRequestFieldNames, "clean-cycle-request", &r)
	return r, err
}

func DecodeRunCleanCycleReply(doc []byte) (RunCleanCycleReply, error) {
	var r RunCleanCycleReply
	err := decodeMiddlemanDocument(doc, runCleanCycleReplyFieldNames, "clean-cycle-reply", &r)
	return r, err
}

func DecodeHealthRequest(doc []byte) (HealthRequest, error) {
	var r HealthRequest
	err := decodeMiddlemanDocument(doc, healthRequestFieldNames, "health-request", &r)
	return r, err
}

func DecodeHealthReply(doc []byte) (HealthReply, error) {
	var r HealthReply
	err := decodeMiddlemanDocument(doc, healthReplyFieldNames, "health-reply", &r)
	return r, err
}

func DecodeSampleMetricsRequest(doc []byte) (SampleMetricsRequest, error) {
	var r SampleMetricsRequest
	err := decodeMiddlemanDocument(doc, sampleMetricsRequestFieldNames, "sample-metrics-request", &r)
	return r, err
}

func DecodeSampleMetricsReply(doc []byte) (SampleMetricsReply, error) {
	var r SampleMetricsReply
	err := decodeMiddlemanDocument(doc, sampleMetricsReplyFieldNames, "sample-metrics-reply", &r)
	return r, err
}

func DecodeTapConsoleRequest(doc []byte) (TapConsoleRequest, error) {
	var r TapConsoleRequest
	err := decodeMiddlemanDocument(doc, tapConsoleRequestFieldNames, "tap-console-request", &r)
	return r, err
}

func DecodeTapConsoleReply(doc []byte) (TapConsoleReply, error) {
	var r TapConsoleReply
	err := decodeMiddlemanDocument(doc, tapConsoleReplyFieldNames, "tap-console-reply", &r)
	return r, err
}

// The wire documents' exact top-level key sets, derived from the
// struct tags at init so they cannot drift from the schema.
var (
	prepareRequestFieldNames       = schemaFieldNames(reflect.TypeFor[PrepareRequest]())
	prepareReplyFieldNames         = schemaFieldNames(reflect.TypeFor[PrepareReply]())
	machineFactsRequestFieldNames  = schemaFieldNames(reflect.TypeFor[MachineFactsRequest]())
	machineFactsReplyFieldNames    = schemaFieldNames(reflect.TypeFor[MachineFactsReply]())
	runCleanCycleRequestFieldNames = schemaFieldNames(reflect.TypeFor[RunCleanCycleRequest]())
	runCleanCycleReplyFieldNames   = schemaFieldNames(reflect.TypeFor[RunCleanCycleReply]())
	healthRequestFieldNames        = schemaFieldNames(reflect.TypeFor[HealthRequest]())
	healthReplyFieldNames          = schemaFieldNames(reflect.TypeFor[HealthReply]())
	sampleMetricsRequestFieldNames = schemaFieldNames(reflect.TypeFor[SampleMetricsRequest]())
	sampleMetricsReplyFieldNames   = schemaFieldNames(reflect.TypeFor[SampleMetricsReply]())
	tapConsoleRequestFieldNames    = schemaFieldNames(reflect.TypeFor[TapConsoleRequest]())
	tapConsoleReplyFieldNames      = schemaFieldNames(reflect.TypeFor[TapConsoleReply]())
)

// decodeMiddlemanDocument is DecodeJobSpec's exact document law applied
// to a middleman wire document: the size bound, the exact-key top-level
// scan, the strict struct decode, and the nothing-trailing check. The
// exact-key scan is a TOP-level guarantee: duplicate or case-variant
// keys nested inside a payload value (a delivery's own fields, say) are
// not scanned and fall through to encoding/json's case-insensitive,
// last-occurrence-wins decode.
func decodeMiddlemanDocument(doc []byte, fieldNames map[string]bool, what string, v any) error {
	if len(doc) > MaxDocumentBytes {
		return ValidationErrors{{
			Field: "document",
			Rule:  RuleDocumentSize,
			Message: fmt.Sprintf("document is %d bytes, at most %d are allowed (the %s rule bounds a document before any parsing)",
				len(doc), MaxDocumentBytes, RuleDocumentSize),
		}}
	}
	if err := checkDocumentKeys(doc, fieldNames, what); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if name, ok := unknownFieldName(err); ok {
			return ValidationErrors{{
				Field:   "document",
				Rule:    RuleUnknownField,
				Message: fmt.Sprintf("document carries an unknown field %q; the schema refuses fields it does not know — and the custody law with them", name),
			}}
		}
		return ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document is not a well-formed " + what + " JSON document: " + err.Error(),
		}}
	}
	// Nothing but whitespace may follow the JSON value.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ValidationErrors{{
			Field:   "document",
			Rule:    RuleMalformed,
			Message: "document carries trailing content after the JSON value",
		}}
	}
	return nil
}

// NewOpEnvelope composes an envelope for op with a fresh op id and a
// deadline of now+span, checking the compose-time battery (Health's
// span is clamped-checked against MaxHealthDeadline by the battery).
// It is the one compose path both sides share, so the deadline law
// cannot be forgotten at a call site.
func NewOpEnvelope(op, opID string, now time.Time, span time.Duration) (Envelope, error) {
	e := Envelope{
		Op:             op,
		OpID:           opID,
		DeadlineUnixMs: now.Add(span).UnixMilli(),
	}
	if errs := ValidateEnvelope(e, now); len(errs) != 0 {
		return Envelope{}, errs
	}
	return e, nil
}
