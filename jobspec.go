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

	// Source names the source tree a BUILD job compiles (the
	// BuildJobSpec class): the repository URL and the exact commit the
	// build pins. Nil on ordinary CI jobs (they carry no source). The
	// commit is the only identity the build trusts — a mutable ref is
	// never carried on the wire.
	Source *SourceRef `json:"source,omitempty"`

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

	// LogTopicID names the event-gateway channel the job's log lines
	// stream through (the BuildJobSpec class's build-log channel; D14).
	// Empty on jobs that stream no logs. It is an identifier, never a
	// credential: a consumer subscribes through the gateway's own
	// fail-closed registration, never through this value.
	LogTopicID string `json:"log_topic_id,omitempty"`
}

// SourceRef is the source tree a build job compiles: the repository
// URL and the exact commit. The commit is the build's only source
// identity — the wire carries no mutable ref, so what the builder
// checks out is exactly what the control plane named.
type SourceRef struct {
	// Repo is the repository URL (https or ssh form). It locates the
	// tree; it carries no credential material — the pull credential
	// travels as a BuildSpec reference.
	Repo string `json:"repo"`

	// Commit is the exact commit the build pins: a full git object id
	// (40 or 64 lowercase hex characters, SHA-1 or SHA-256).
	Commit string `json:"commit"`
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

// BuildSpec carries the `build` step fields. It serves two shapes of
// the same field set:
//
//   - the BuildJobSpec class (a git-source build): Strategy names the
//     build strategy and the plan rows carry the RESOLVED build plan
//     (the Session-32 build-block grammar — strategy, runtime,
//     install, build, start — mirrored field for field; the contracts
//     module imports no deploykit types). The pull and push
//     credentials travel as credential-store REFERENCES, never values.
//   - the legacy CI build shape (a daemonless image build): only
//     BaseImage is set, digest-only. Strategy stays empty there, and
//     the validation battery keeps the historical rules for it.
type BuildSpec struct {
	// BaseImage is the digest-only image the build runs from. On the
	// BuildJobSpec class it is the digest-pinned builder image (the
	// D4 pinning law); on the legacy CI shape it is the build's base.
	BaseImage string `json:"base_image"`

	// Strategy is the build strategy: plan | dockerfile (the
	// blueprint build-block vocabulary, mirrored). Required for the
	// BuildJobSpec class; empty on the legacy CI shape.
	Strategy string `json:"strategy,omitempty"`

	// Runtime is the engine-resolved runtime ("node:22") — a plan row,
	// evidence-carrying, not a pulled reference (it is not bound by
	// the digest-only law; the builder image itself is).
	Runtime string `json:"runtime,omitempty"`

	// Install is the install command ("npm ci").
	Install string `json:"install,omitempty"`

	// Build is the build command ("npm run build").
	Build string `json:"build,omitempty"`

	// Start is the keep-alive start command ("npm start") — the
	// crash → restart, logs-stay contract. Required on the
	// BuildJobSpec class (both strategies).
	Start string `json:"start,omitempty"`

	// Port is the service's serving port (0 = none declared).
	Port int `json:"port,omitempty"`

	// SourcePullCredential names the credential-store key the builder
	// exchanges for THE source pull (read-only, scoped to the one
	// repository). A reference, never a value: the grammar is the
	// credential-store:// form, and inline secret material is refused
	// by the validation battery (the isolation negative-set).
	SourcePullCredential string `json:"source_pull_credential,omitempty"`

	// RegistryPushCredential names the credential-store key the
	// builder exchanges for THE image push (the one push target).
	// Same reference-only law as SourcePullCredential.
	RegistryPushCredential string `json:"registry_push_credential,omitempty"`
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
