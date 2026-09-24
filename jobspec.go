package contracts

// JobSpec is the signed wire document the engine hands to a runner
// (the Tier V node-host agent or the Tier H pool agent). It is the ONE
// schema for both tiers (two trust anchors, one document shape).
//
// Every image-bearing field is digest-only: references must be of the
// form registry/path@sha256:<64 lowercase hex>. A mutable tag, the
// latest tag, or any non-digest reference is refused by the validation
// battery with the field and the offending reference named.
//
// Env entries never carry inline secrets: an entry is either a plain
// value or a reference naming a platform credential-store key, which
// the Pool Manager resolves at dispatch and injects per job.
type JobSpec struct {
	// JobID is the platform-generated unique job identifier.
	JobID string `json:"job_id"`

	// RunReference names the pipeline run this job belongs to. It is
	// stable across attempts of the same job.
	RunReference string `json:"run_reference"`

	// Attempt is the 1-based attempt counter. The idempotency key is
	// the pair (RunReference, Attempt): the pool refuses a duplicate
	// key, while a refused or errored submission does not register its
	// key, so the legitimate retry with the same key is accepted.
	Attempt int `json:"attempt"`

	// Image is the digest-only container image the job's command runs
	// in (the `run` step image).
	Image string `json:"image"`

	// Command is the argv the job runs. It is required and every entry
	// must be non-empty.
	Command []string `json:"command,omitempty"`

	// Services are sibling containers started alongside the job (the
	// `service` step containers, typically test dependencies). Images
	// are digest-only.
	Services []ServiceContainer `json:"services,omitempty"`

	// Build carries the `build` step fields when the job builds an
	// image (daemonless builders). The base image is digest-only; the
	// built digest flows to push through artifact outputs.
	Build *BuildSpec `json:"build,omitempty"`

	// Env carries environment entries: plain values and/or
	// credential-store secret references. References name keys; they
	// never carry secret material.
	Env []EnvEntry `json:"env,omitempty"`

	// ArtifactInputs are digest-pinned OCI references consumed by the
	// job. The digest-only law extends to them.
	ArtifactInputs []ArtifactInput `json:"artifact_inputs,omitempty"`

	// ArtifactOutputs are the `push`-side destinations the job's
	// artifacts go to in the customer's registry. Output tags are
	// deliberately exempt from the digest-only law: they are applied
	// at push time and are never used to pull.
	ArtifactOutputs []ArtifactOutput `json:"artifact_outputs,omitempty"`

	// TimeoutSeconds bounds the job's wall clock. The platform's
	// watchdog enforces an independent maximum on top of it.
	TimeoutSeconds int `json:"timeout_seconds"`

	// Limits are the job's resource limits. All three are required,
	// positive, and bounded.
	Limits ResourceLimits `json:"limits"`

	// EgressAllowlist lists hostname suffixes the job may contact. An
	// empty list is legal and means deny-all. Matching is
	// hostname-suffix based (registries serve blobs from CDNs) and is
	// enforced at the container/network level on the runner VM.
	EgressAllowlist []string `json:"egress_allowlist"`

	// MeteringTags are key/value pairs attached to the job's metering
	// events. Keys are constrained ([a-z0-9_-], max length) and the
	// count is bounded.
	MeteringTags map[string]string `json:"metering_tags"`
}

// ServiceContainer is a sibling container started alongside the job.
type ServiceContainer struct {
	// Name is the container's name within the job; unique across the
	// job's services.
	Name string `json:"name"`

	// Image is the digest-only container image.
	Image string `json:"image"`

	// Command is the optional argv for the container; when empty the
	// image's entrypoint runs.
	Command []string `json:"command,omitempty"`
}

// BuildSpec carries the `build` step fields.
type BuildSpec struct {
	// BaseImage is the digest-only image the build runs from.
	BaseImage string `json:"base_image"`
}

// EnvEntry is one environment entry. Exactly one of Value and
// SecretReference must be set: either a plain value (which may be the
// empty string) or a reference naming a platform credential-store key.
type EnvEntry struct {
	Name string `json:"name"`

	// Value is the plain value. A pointer makes an empty-string value
	// distinguishable from an absent one on the wire.
	Value *string `json:"value,omitempty"`

	// SecretReference names a credential-store key in the
	// credential-store:// namespace. The Pool Manager resolves it at
	// dispatch and injects it per job; it is never at rest and never
	// inline.
	SecretReference *string `json:"secret_reference,omitempty"`
}

// ArtifactInput is a digest-pinned OCI reference the job consumes.
type ArtifactInput struct {
	Name      string `json:"name"`
	Reference string `json:"reference"`
}

// ArtifactOutput is a destination for the job's artifacts in the
// customer's registry. Repository is a path (no tag, no digest); tags
// are applied at push time.
type ArtifactOutput struct {
	Name       string   `json:"name"`
	Repository string   `json:"repository"`
	Tags       []string `json:"tags,omitempty"`
}

// ResourceLimits are the job's resource limits. All three are required,
// positive, and bounded by the Max* constants.
type ResourceLimits struct {
	// CPUMillicores is the CPU allowance in millicores (1000 = one
	// core).
	CPUMillicores int64 `json:"cpu_millicores"`

	// MemoryBytes is the memory allowance in bytes.
	MemoryBytes int64 `json:"memory_bytes"`

	// DiskBytes is the disk allowance in bytes (the disk cap).
	DiskBytes int64 `json:"disk_bytes"`
}

// IdempotencyKey is the job's idempotency key: the pair (run reference,
// attempt). The pool refuses a duplicate key with a named reason, and a
// submission refused or errored does not register its key, so the
// legitimate retry with the same key is accepted.
type IdempotencyKey struct {
	RunReference string `json:"run_reference"`
	Attempt      int    `json:"attempt"`
}

// IdempotencyKey returns the job's idempotency key: the pair of the run
// reference and the attempt number.
func (s JobSpec) IdempotencyKey() IdempotencyKey {
	return IdempotencyKey{RunReference: s.RunReference, Attempt: s.Attempt}
}
