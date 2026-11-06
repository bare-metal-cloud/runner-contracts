package contracts

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The machine-side middleman protocol: the versioned wire contract the
// machine's agent and the runnermand daemon (the supervised
// machine-side middleman binary) speak to each other over a local unix
// socket. Both sides import THIS module — the both-import law — so the
// exact wire definitions exist once and neither side can drift its
// copy.
//
// The boundary the protocol encodes: the daemon executes and observes
// ON the machine (install, clean, facts, metrics, console tap), the
// agent owns everything that talks to the platform. The custody law
// shapes the wire from day one — Delivery carries the verified payload
// only; the completion signing seed is not a wire field anywhere in the
// protocol; the registration token crosses only at install, inside the
// named fresh-token field, one shot per delivery attempt. The refusal
// vocabulary (refusal.go) and the connect-time version handshake
// (handshake.go) complete the wire.

// ProtocolVersion is the protocol version the connect-time handshake
// announces and answers. Version 1 is EXACT-MATCH-ONLY: a handshake
// admits equal versions and negotiates no compatible range. A protocol
// change is a new ProtocolVersion with its own compat battery (the test
// pin law: a failing protocol-compatibility test blocks a new version's
// release).
const ProtocolVersion = 1

// The op set: the six verbs the daemon answers, and nothing else. There
// is no shell, no escape hatch, no pass-through op — a request whose op
// is not one of these names is refused by name (RefusalUnknownOp).
//
// The lifecycle is two verbs, not four: cancel is the forge-side cancel
// plus one RunCleanCycle; resume is Prepare again. No Suspend/Resume
// ops exist in the protocol.
const (
	OpPrepare       = "prepare"
	OpMachineFacts  = "machine_facts"
	OpRunCleanCycle = "run_clean_cycle"
	OpHealth        = "health"
	OpSampleMetrics = "sample_metrics"
	OpTapConsole    = "tap_console"
)

// IsMiddlemanOp reports whether op is a name in the protocol's op set.
func IsMiddlemanOp(op string) bool {
	switch op {
	case OpPrepare, OpMachineFacts, OpRunCleanCycle,
		OpHealth, OpSampleMetrics, OpTapConsole:
		return true
	}
	return false
}

// MachineMiddleman is the op set, as both sides implement or consume it.
// The wire encoding of every op lives in this module (middleman_wire.go);
// the version handshake runs on connect before any op (handshake.go).
//
//	Prepare       — verify + install + launch the forge runner
//	MachineFacts  — the machine facts placement reads
//	RunCleanCycle — plant/scrub/receipt over ledger-named targets
//	Health        — the liveness probe (a short deadline; see
//	                MaxHealthDeadline)
//	SampleMetrics — cpu/mem/disk per runner/slice over a window (feeds
//	                Insights/Usage; best-effort and lossy by design)
//	TapConsole    — the live console tap (mirrors into the capture
//	                pipeline; masked stream only)
type MachineMiddleman interface {
	Prepare(ctx context.Context, delivery Delivery) (RunnerHandle, error)
	MachineFacts(ctx context.Context) Facts
	RunCleanCycle(ctx context.Context, op CleanOp) (Receipt, error)
	Health(ctx context.Context) HealthReport
	SampleMetrics(ctx context.Context, window MetricsWindow) (RunnerMetrics, error)
	TapConsole(ctx context.Context, job JobRef) (LogStream, error)
}

// The forge kinds a delivery may name. The installer is per-kind behind
// one interface; the wire names the kind so the daemon never guesses.
const (
	ForgeGitHub  = "github"
	ForgeGitLab  = "gitlab"
	ForgeForgejo = "forgejo"
)

func isForgeKind(f string) bool {
	switch f {
	case ForgeGitHub, ForgeGitLab, ForgeForgejo:
		return true
	}
	return false
}

// Delivery is the install-scoped payload Prepare hands the daemon: the
// VERIFIED payload only — the start render, the digest pin, the
// artifacts — never custody material beyond the one permitted crossing.
//
// The custody law, enforced by the shape itself:
//
//   - the completion signing seed is not a field of this document (nor
//     of any document in the protocol): the agent keeps the seed and
//     signs the terminal itself;
//   - FreshRegistrationToken is the registration token's ONLY wire
//     home: it crosses at install, one shot per delivery attempt, is
//     held for the install's duration, and is never persisted by the
//     daemon — not to disk, not to logs;
//   - DeliveryAttempt names the one-shot attempt: a Prepare retry is
//     the SAME delivery identity with DeliveryAttempt incremented and a
//     FRESH token (the forge-side registration may have consumed the
//     earlier one). The fresh-token re-delivery is the named retry
//     shape; there is no daemon-side token cache.
//
// The strict decoder refuses any field the schema does not know, so a
// document carrying signing material is refused by name, and the
// golden fixture pins the exact key set so a custody-material field
// cannot join the schema silently.
type Delivery struct {
	// DeliveryAttempt is the 1-based one-shot counter for this
	// delivery identity. Each attempt carries its own fresh token.
	DeliveryAttempt int `json:"delivery_attempt"`

	// JobID, RunReference, and Attempt are the platform job identity
	// the delivery belongs to (the same triple the signed start
	// terminal echoes).
	JobID        string `json:"job_id"`
	RunReference string `json:"run_reference"`
	Attempt      int    `json:"attempt"`

	// Forge is the forge kind whose runner this delivery installs.
	Forge string `json:"forge"`

	// StartRender is the ONE validated start render, composed
	// control-plane-side. The daemon executes it as delivered; no
	// second render exists anywhere on the machine.
	StartRender string `json:"start_render"`

	// FreshRegistrationToken is the attempt's registration token. It
	// is required on every delivery (every Prepare is an install
	// attempt) and is the only custody material the protocol ever
	// carries.
	FreshRegistrationToken string `json:"fresh_registration_token"`

	// DigestPin is the sha256 pin of the runner binary the rail
	// serves. The installer verifies it fail-closed: a mismatch
	// refuses the install, never falls back to an unpinned fetch.
	DigestPin string `json:"digest_pin"`

	// Artifacts are the digest-pinned artifacts the install consumes.
	Artifacts []DeliveryArtifact `json:"artifacts,omitempty"`
}

// DeliveryArtifact is one digest-pinned artifact reference inside a
// delivery. Digest is the sha256 pin; Reference names the rail
// locator. The digest is verified against the exact bytes installed
// and launched.
type DeliveryArtifact struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// ValidateDelivery runs the delivery's validation battery and returns
// every finding. An empty return means the delivery is valid.
func ValidateDelivery(d Delivery) ValidationErrors {
	var errs ValidationErrors

	if d.DeliveryAttempt < 1 {
		errs = append(errs, ValidationError{
			Field:   "delivery.delivery_attempt",
			Rule:    RuleDeliveryAttempt,
			Message: "delivery_attempt must be at least 1 (attempts are a 1-based counter; each attempt re-delivers a fresh token)",
		})
	}
	errs = append(errs, validateJobIDField("delivery.job_id", d.JobID)...)
	errs = append(errs, validateRunReferenceField("delivery.run_reference", d.RunReference)...)
	if d.Attempt < 1 {
		errs = append(errs, ValidationError{
			Field:   "delivery.attempt",
			Rule:    RuleAttempt,
			Message: "attempt must be at least 1 (attempts are a 1-based counter)",
		})
	}
	if !isForgeKind(d.Forge) {
		errs = append(errs, ValidationError{
			Field:   "delivery.forge",
			Rule:    RuleForge,
			Message: "forge must be one of github, gitlab, forgejo (the daemon never guesses the kind)",
		})
	}
	if d.StartRender == "" {
		errs = append(errs, required("delivery.start_render"))
	}
	if d.FreshRegistrationToken == "" {
		errs = append(errs, ValidationError{
			Field:   "delivery.fresh_registration_token",
			Rule:    RuleRegistrationToken,
			Message: "fresh_registration_token is required (the registration token crosses only at install, one shot per delivery attempt)",
		})
	} else if len(d.FreshRegistrationToken) > MaxRegistrationTokenLength {
		errs = append(errs, ValidationError{
			Field:   "delivery.fresh_registration_token",
			Rule:    RuleRegistrationToken,
			Message: fmt.Sprintf("fresh_registration_token is %d characters, at most %d are allowed", len(d.FreshRegistrationToken), MaxRegistrationTokenLength),
		})
	}
	if v, bad := digestPinError("delivery.digest_pin", d.DigestPin); bad {
		errs = append(errs, v)
	}
	if len(d.Artifacts) > MaxDeliveryArtifacts {
		errs = append(errs, ValidationError{
			Field:   "delivery.artifacts",
			Rule:    RuleArtifactCount,
			Message: fmt.Sprintf("delivery carries %d artifacts, at most %d are allowed", len(d.Artifacts), MaxDeliveryArtifacts),
		})
	}
	for i, a := range d.Artifacts {
		if a.Name == "" {
			errs = append(errs, required(fmt.Sprintf("delivery.artifacts[%d].name", i)))
		}
		if a.Reference == "" {
			errs = append(errs, required(fmt.Sprintf("delivery.artifacts[%d].reference", i)))
		}
		if v, bad := digestPinError(fmt.Sprintf("delivery.artifacts[%d].digest", i), a.Digest); bad {
			errs = append(errs, v)
		}
	}
	return errs
}

// RunnerHandle is what a successful Prepare returns: the daemon's
// ledger identity for the launched runner. HandleID is the key the
// daemon's ledger (and later clean cycles) know it by; ServiceUnit is
// the systemd unit the daemon launched it under.
type RunnerHandle struct {
	HandleID        string `json:"handle_id"`
	Forge           string `json:"forge"`
	JobID           string `json:"job_id"`
	RunReference    string `json:"run_reference"`
	Attempt         int    `json:"attempt"`
	ServiceUnit     string `json:"service_unit"`
	StartedAtUnixMs int64  `json:"started_at_unix_ms"`
}

// ValidateRunnerHandle checks a handle's shape.
func ValidateRunnerHandle(h RunnerHandle) ValidationErrors {
	var errs ValidationErrors
	if h.HandleID == "" {
		errs = append(errs, required("handle.handle_id"))
	} else if len(h.HandleID) > MaxNameLength || !jobIDRe.MatchString(h.HandleID) {
		errs = append(errs, ValidationError{
			Field:   "handle.handle_id",
			Rule:    RuleHandleID,
			Message: "handle_id must be at most 63 characters of letters, digits, dots, hyphens, and underscores, starting with a letter or digit",
		})
	}
	if !isForgeKind(h.Forge) {
		errs = append(errs, ValidationError{Field: "handle.forge", Rule: RuleForge, Message: "forge must be one of github, gitlab, forgejo"})
	}
	errs = append(errs, validateJobIDField("handle.job_id", h.JobID)...)
	errs = append(errs, validateRunReferenceField("handle.run_reference", h.RunReference)...)
	if h.Attempt < 1 {
		errs = append(errs, ValidationError{Field: "handle.attempt", Rule: RuleAttempt, Message: "attempt must be at least 1"})
	}
	if h.ServiceUnit == "" {
		errs = append(errs, required("handle.service_unit"))
	}
	if h.StartedAtUnixMs <= 0 {
		errs = append(errs, ValidationError{Field: "handle.started_at_unix_ms", Rule: RuleDeadline, Message: "started_at_unix_ms must be a positive epoch-milliseconds timestamp"})
	}
	return errs
}

// Facts is what MachineFacts answers: the machine facts placement
// reads, plus the boot reconciliation's drift (what the daemon found
// inconsistent about its own prior life on start).
type Facts struct {
	Hostname      string  `json:"hostname"`
	Arch          string  `json:"arch"`           // uname -m (x86_64, aarch64)
	OS            string  `json:"os"`             // os-release ID (linux)
	OSVersion     string  `json:"os_version"`     // os-release PRETTY_NAME
	KernelVersion string  `json:"kernel_version"` // uname -r
	MachineID     string  `json:"machine_id"`     // the machine-id fingerprint
	Drift         []Drift `json:"drift,omitempty"`
}

// Drift is one boot-reconciliation finding: something the daemon
// inventoried inconsistent with its ledger. The pool reads drift
// through Health and MachineFacts and destroy-pends the machine on it.
type Drift struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// The named drift kinds.
const (
	DriftStageDir     = "stage-dir"     // a leftover op-id/digest-keyed stage dir
	DriftHalfInstall  = "half-install"  // a half-completed install the ledger cannot resume
	DriftServiceState = "service-state" // an installed runner service in an unexpected state
)

func isDriftKind(k string) bool {
	switch k {
	case DriftStageDir, DriftHalfInstall, DriftServiceState:
		return true
	}
	return false
}

// ValidateFacts checks the facts document's shape.
func ValidateFacts(f Facts) ValidationErrors {
	var errs ValidationErrors
	if f.Hostname == "" {
		errs = append(errs, required("facts.hostname"))
	}
	if f.Arch == "" {
		errs = append(errs, required("facts.arch"))
	}
	if f.OS == "" {
		errs = append(errs, required("facts.os"))
	}
	if f.MachineID == "" {
		errs = append(errs, required("facts.machine_id"))
	}
	for i, d := range f.Drift {
		if !isDriftKind(d.Kind) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("facts.drift[%d].kind", i),
				Rule:    RuleDriftKind,
				Message: "drift kind must be one of stage-dir, half-install, service-state",
			})
		}
		if d.Detail == "" {
			errs = append(errs, required(fmt.Sprintf("facts.drift[%d].detail", i)))
		}
	}
	return errs
}

// CleanOp is the RunCleanCycle input. The bounds law shapes it: every
// target validates against the daemon's OWN ledger — the planted
// containers, the managed paths, and the stage directories this daemon
// created and its receipts name. A target the ledger does not know is
// refused by name (RefusalUnknownTarget): the daemon's receipts, not
// the request, are the allowlist.
type CleanOp struct {
	Targets []CleanTarget `json:"targets"`
}

// CleanTarget is one thing a clean cycle scrubs. Kind is one of the
// named target kinds; Ref is the ledger's reference for it.
type CleanTarget struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// The named clean-target kinds.
const (
	CleanTargetContainer = "container" // a planted container the daemon owns
	CleanTargetPath      = "path"      // a managed path the daemon created
	CleanTargetStage     = "stage"     // an op-id/digest-keyed stage dir
)

func isCleanTargetKind(k string) bool {
	switch k {
	case CleanTargetContainer, CleanTargetPath, CleanTargetStage:
		return true
	}
	return false
}

// ValidateCleanOp checks the clean op's shape (the ledger allowlist is
// the daemon's runtime duty; this battery checks the document's).
func ValidateCleanOp(op CleanOp) ValidationErrors {
	var errs ValidationErrors
	if len(op.Targets) > MaxCleanTargets {
		errs = append(errs, ValidationError{
			Field:   "clean.targets",
			Rule:    RuleCleanTargetCount,
			Message: fmt.Sprintf("clean op names %d targets, at most %d are allowed", len(op.Targets), MaxCleanTargets),
		})
	}
	for i, t := range op.Targets {
		if !isCleanTargetKind(t.Kind) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("clean.targets[%d].kind", i),
				Rule:    RuleCleanTargetKind,
				Message: "target kind must be one of container, path, stage",
			})
		}
		if t.Ref == "" {
			errs = append(errs, required(fmt.Sprintf("clean.targets[%d].ref", i)))
		} else if containsWhitespace(t.Ref) {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("clean.targets[%d].ref", i),
				Rule:    RuleCleanTargetRef,
				Message: "target ref must carry no whitespace (it is a ledger reference, never free text)",
			})
		}
	}
	return errs
}

// Receipt is what RunCleanCycle returns: the cycle's record, which is
// the clean-op bounds law's allowlist of record. CycleID is the
// request's op id echoed — a re-run of the same op answers with the
// same receipt identity. Scrubbed names the targets the cycle scrubbed
// (the ledger entries this receipt now proves were cleaned).
type Receipt struct {
	CycleID  string        `json:"cycle_id"`
	Scrubbed []CleanTarget `json:"scrubbed"`
	AtUnixMs int64         `json:"at_unix_ms"`
}

// ValidateReceipt checks a receipt's shape.
func ValidateReceipt(r Receipt) ValidationErrors {
	var errs ValidationErrors
	if r.CycleID == "" {
		errs = append(errs, required("receipt.cycle_id"))
	} else if len(r.CycleID) > MaxOpIDLength || !jobIDRe.MatchString(r.CycleID) {
		errs = append(errs, ValidationError{Field: "receipt.cycle_id", Rule: RuleOpID, Message: "cycle_id must be the request's op id (the op-id grammar)"})
	}
	if r.AtUnixMs <= 0 {
		errs = append(errs, ValidationError{Field: "receipt.at_unix_ms", Rule: RuleDeadline, Message: "at_unix_ms must be a positive epoch-milliseconds timestamp"})
	}
	for i, t := range r.Scrubbed {
		if !isCleanTargetKind(t.Kind) {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("receipt.scrubbed[%d].kind", i), Rule: RuleCleanTargetKind, Message: "target kind must be one of container, path, stage"})
		}
		if t.Ref == "" {
			errs = append(errs, required(fmt.Sprintf("receipt.scrubbed[%d].ref", i)))
		}
	}
	return errs
}

// HealthReport is what Health answers: the liveness probe's payload
// (see MaxHealthDeadline — a Health that cannot answer quickly is an
// unhealthy machine, not a slow one), the daemon's build identity, the
// op currently in flight (the serialization law's visible state), and
// any boot-reconciliation drift.
type HealthReport struct {
	Healthy       bool    `json:"healthy"`
	DaemonVersion string  `json:"daemon_version"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	InFlightOp    string  `json:"in_flight_op,omitempty"` // empty when idle; an op-set name when a mutating op is running
	Drift         []Drift `json:"drift,omitempty"`
}

// ValidateHealthReport checks a health report's shape.
func ValidateHealthReport(h HealthReport) ValidationErrors {
	var errs ValidationErrors
	if h.DaemonVersion == "" {
		errs = append(errs, required("health.daemon_version"))
	}
	if h.InFlightOp != "" && !IsMiddlemanOp(h.InFlightOp) {
		errs = append(errs, ValidationError{Field: "health.in_flight_op", Rule: RuleOpName, Message: "in_flight_op must be empty (idle) or an op-set name"})
	}
	for i, d := range h.Drift {
		if !isDriftKind(d.Kind) {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("health.drift[%d].kind", i), Rule: RuleDriftKind, Message: "drift kind must be one of stage-dir, half-install, service-state"})
		}
		if d.Detail == "" {
			errs = append(errs, required(fmt.Sprintf("health.drift[%d].detail", i)))
		}
	}
	return errs
}

// MetricsWindow names the window SampleMetrics samples: epoch
// milliseconds, from inclusive to exclusive.
type MetricsWindow struct {
	FromUnixMs int64 `json:"from_unix_ms"`
	ToUnixMs   int64 `json:"to_unix_ms"`
}

// ValidateMetricsWindow checks the window's shape.
func ValidateMetricsWindow(w MetricsWindow) ValidationErrors {
	var errs ValidationErrors
	if w.FromUnixMs <= 0 || w.ToUnixMs <= 0 {
		errs = append(errs, ValidationError{Field: "window", Rule: RuleDeadline, Message: "from_unix_ms and to_unix_ms must be positive epoch-milliseconds timestamps"})
		return errs
	}
	if w.ToUnixMs <= w.FromUnixMs {
		errs = append(errs, ValidationError{Field: "window", Rule: RuleMetricsWindow, Message: "to_unix_ms must be after from_unix_ms"})
	}
	if w.ToUnixMs-w.FromUnixMs > int64(MaxMetricsWindow/time.Millisecond) {
		errs = append(errs, ValidationError{Field: "window", Rule: RuleMetricsWindow, Message: fmt.Sprintf("the window spans %d ms, at most %d ms are sampled in one request", w.ToUnixMs-w.FromUnixMs, MaxMetricsWindow/time.Millisecond)})
	}
	return errs
}

// RunnerMetrics is what SampleMetrics answers: the sampled cpu/mem/disk
// per runner and per slice over the asked window. Best-effort and lossy
// by design — a gap in the samples is a gap in the charts, never an
// error surfaced to a job.
type RunnerMetrics struct {
	Window  MetricsWindow  `json:"window"`
	Samples []MetricSample `json:"samples"`
}

// MetricSample is one sample point: the runner handle and slice it
// belongs to, the sampled resources, and the sample time.
type MetricSample struct {
	Runner        string `json:"runner"`         // the RunnerHandle id
	Slice         string `json:"slice"`          // the slice identity on the machine
	CPUMillicores int64  `json:"cpu_millicores"` // integer millicores — no floats on the canonical wire
	MemoryBytes   int64  `json:"memory_bytes"`
	DiskBytes     int64  `json:"disk_bytes"`
	AtUnixMs      int64  `json:"at_unix_ms"`
}

// ValidateRunnerMetrics checks the metrics document's shape.
func ValidateRunnerMetrics(m RunnerMetrics) ValidationErrors {
	var errs ValidationErrors
	errs = append(errs, ValidateMetricsWindow(m.Window)...)
	if len(m.Samples) > MaxMetricSamples {
		errs = append(errs, ValidationError{Field: "metrics.samples", Rule: RuleMetricSampleCount, Message: fmt.Sprintf("metrics carry %d samples, at most %d are allowed in one reply", len(m.Samples), MaxMetricSamples)})
	}
	for i, s := range m.Samples {
		if s.Runner == "" {
			errs = append(errs, required(fmt.Sprintf("metrics.samples[%d].runner", i)))
		}
		if s.Slice == "" {
			errs = append(errs, required(fmt.Sprintf("metrics.samples[%d].slice", i)))
		}
		if s.AtUnixMs <= 0 {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("metrics.samples[%d].at_unix_ms", i), Rule: RuleDeadline, Message: "at_unix_ms must be a positive epoch-milliseconds timestamp"})
		}
	}
	return errs
}

// JobRef names the job a TapConsole taps: the platform job attempt, and
// the sequence cursor the agent resumes from — the sequence number is
// the merge key the capture pipeline dedupes a re-tap's replay by, so
// a fresh TapConsole never double-counts a line.
type JobRef struct {
	JobID        string `json:"job_id"`
	RunReference string `json:"run_reference"`
	Attempt      int    `json:"attempt"`
	FromSequence int64  `json:"from_sequence"` // 0 taps from the stream's start
}

// ValidateJobRef checks the job reference's shape.
func ValidateJobRef(j JobRef) ValidationErrors {
	var errs ValidationErrors
	errs = append(errs, validateJobIDField("job.job_id", j.JobID)...)
	errs = append(errs, validateRunReferenceField("job.run_reference", j.RunReference)...)
	if j.Attempt < 1 {
		errs = append(errs, ValidationError{Field: "job.attempt", Rule: RuleAttempt, Message: "attempt must be at least 1"})
	}
	if j.FromSequence < 0 {
		errs = append(errs, ValidationError{Field: "job.from_sequence", Rule: RuleSequence, Message: "from_sequence must be at least 0 (a sequence cursor, never negative)"})
	}
	return errs
}

// LogStream is one streamed tap record: the tap session's identity, the
// job line at its sequence position, and the masked-stream stance the
// wire carries as a field. Masked is always true in v1 — the capture
// point is the MASKED stream (the runners apply their registered-secret
// masks to the console stream they emit; the daemon tails exactly that
// stream, never the raw diagnostic output) — and the battery refuses a
// record that declares otherwise.
type LogStream struct {
	StreamID string `json:"stream_id"` // the tap session's identity (a re-tap opens a new one)
	JobID    string `json:"job_id"`
	Sequence int64  `json:"sequence"` // the merge key: the capture pipeline dedupes replays by it
	Masked   bool   `json:"masked"`   // always true in v1; a false value is refused by the battery
	Line     string `json:"line"`
	EOF      bool   `json:"eof"` // the tap session's end marker
}

// ValidateLogStream checks a tap record's shape and the masked-stream
// stance.
func ValidateLogStream(s LogStream) ValidationErrors {
	var errs ValidationErrors
	if s.StreamID == "" {
		errs = append(errs, required("stream.stream_id"))
	}
	errs = append(errs, validateJobIDField("stream.job_id", s.JobID)...)
	if s.Sequence < 0 {
		errs = append(errs, ValidationError{Field: "stream.sequence", Rule: RuleSequence, Message: "sequence must be at least 0 (the merge key, never negative)"})
	}
	if !s.Masked {
		errs = append(errs, ValidationError{Field: "stream.masked", Rule: RuleMaskedStream, Message: "masked must be true: the tap's capture point is the masked stream, never the runner's raw diagnostic output"})
	}
	if s.Line == "" && !s.EOF {
		errs = append(errs, required("stream.line"))
	}
	return errs
}

// validateJobIDField applies the job-id grammar to a middleman
// document's job-id field (the same rules and bounds as the job-spec
// schema's job_id).
func validateJobIDField(field, id string) ValidationErrors {
	if id == "" {
		return ValidationErrors{required(field)}
	}
	if len(id) > MaxJobIDLength || !jobIDRe.MatchString(id) {
		return ValidationErrors{{
			Field: field,
			Rule:  RuleJobID,
			Message: fmt.Sprintf("%s %q must be at most %d characters of letters, digits, dots, hyphens, and underscores, starting with a letter or digit",
				field, id, MaxJobIDLength),
		}}
	}
	return nil
}

// validateRunReferenceField applies the run-reference grammar (at most
// MaxRunReferenceLength characters, no whitespace).
func validateRunReferenceField(field, ref string) ValidationErrors {
	if ref == "" {
		return ValidationErrors{required(field)}
	}
	if len(ref) > MaxRunReferenceLength || containsWhitespace(ref) {
		return ValidationErrors{{
			Field: field,
			Rule:  RuleRunReference,
			Message: fmt.Sprintf("%s %q must be at most %d characters and carry no whitespace",
				field, ref, MaxRunReferenceLength),
		}}
	}
	return nil
}

// digestPinError enforces the digest-pin law for one middleman field:
// the pin is the bare sha256 form (sha256: followed by 64 lowercase hex
// characters) — the rail artifact's content identity, verified
// fail-closed before any install.
func digestPinError(field, pin string) (ValidationError, bool) {
	invalid := func(reason string) (ValidationError, bool) {
		return ValidationError{
			Field: field,
			Rule:  RuleDigestPin,
			Message: fmt.Sprintf("digest pin %q is not a bare sha256 pin (%s); the pin is only ever sha256:<64 lowercase hex>",
				pin, reason),
		}, true
	}
	algo, body, ok := strings.Cut(pin, ":")
	if !ok || algo != "sha256" {
		return invalid("the algorithm must be sha256")
	}
	if !isLowerHex64(body) {
		return invalid("the digest body must be 64 lowercase hex characters")
	}
	return ValidationError{}, false
}
