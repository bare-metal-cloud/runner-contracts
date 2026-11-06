# runner-contracts

The neutral, signed job-spec wire contract for BMC runners: the job-spec
schema, its validation battery, the canonical JSON encoding, Ed25519
signing and verification, the typed reason vocabulary, and the build
cancel verb (the signed directive that stops a running attempt). One
schema, many consumers: the engine signs job specs, the agent
job-handler verifies and executes them, and the Pool Manager verifies
and admits them.

The module also carries the machine-side middleman protocol: the
versioned wire contract the machine's agent and the runnermand daemon
speak over their local unix socket, defined once here because both
sides import it (the both-import law). It covers the six ops
(Prepare, MachineFacts, RunCleanCycle, Health, SampleMetrics,
TapConsole) with their request and reply envelopes, the connect-time
version handshake, and the typed refusal vocabulary. See "The
machine-side middleman protocol" below.

The module has zero dependencies (Go standard library only) and imports
nothing private, so it is safe to publish and safe to vendor into any
consumer. Licensed under Apache-2.0.

## The laws of the wire schema

- **Digest-only images.** Every image-bearing field — the run image, the
  service container images, the build base image, and the artifact input
  references — must be of the form `<repository>@sha256:<64 lowercase
  hex>`. A mutable tag, the `latest` tag, a bare repository, a short
  digest, a foreign digest algorithm, or an uppercase digest is refused
  with the field and the offending reference named. Artifact output
  tags are deliberately exempt: they are applied at push time and are
  never used to pull.
- **Secrets are references, never values.** An environment entry is
  either a plain value (which may be the empty string) or a
  `credential-store://<namespace>/<key>` reference naming a platform
  credential-store key, which the Pool Manager resolves at dispatch and
  injects per job.
- **An empty egress allowlist is legal and means deny-all.** Entries are
  hostname suffixes (`registry.acme.example` matches
  `blob.registry.acme.example` but not `evilregistry.acme.example`);
  matching is enforced at the container and network level on the runner.
- **Strict decode.** `DecodeJobSpec` refuses a document that carries any
  field the schema does not know, and names the field. Keys are matched
  case-sensitively (a `JOB_ID` variant is refused, not folded into
  `job_id`), duplicate keys are refused instead of silently
  last-value-wins, and a document larger than `MaxDocumentBytes` (1 MiB)
  is refused before any parsing.
- **Canonical form where signatures live.** `CanonicalJSON` produces a
  deterministic byte form (struct field order, sorted map keys, compact,
  no HTML escaping). `Verify` refuses a document whose bytes are not that
  form, even when the JSON content is equivalent, so a signature always
  covers exactly the bytes both consumers see.
- **Verify validates.** `Verify` mirrors `Sign`'s validate-then-act law:
  after the signature check passes, the parsed spec runs the full
  validation battery. A valid signature over an invalid spec (possible
  only when the signer bypassed `Sign`) is refused by the spec's failing
  rule, so "Verify returned nil" means the document is canonical,
  authentic, and valid.
- **Bounded documents.** The schema's counts are sanity-bounded by named
  maxima (services, env entries, artifact inputs and outputs, egress
  allowlist entries, argv length per command, push-time tags per output,
  metering tags) and a whole-document raw-size cap
  (`MaxDocumentBytes`), so no document can force unbounded work.
- **Idempotency by construction.** The job's idempotency key is the pair
  `(run_reference, attempt)`; the pool refuses a duplicate key, while a
  refused or errored submission does not register its key, so the
  legitimate retry with the same key is accepted.

## Usage

Sign a job spec (the engine side), then verify and decode it (the
consumer side):

```go
sig, err := contracts.Sign(engineKey, spec)
if err != nil {
    return err // a typed contracts.ValidationErrors; Sign refuses to sign an invalid spec
}

doc, err := contracts.CanonicalJSON(spec)
if err != nil {
    return err
}
if err := contracts.Verify(publicKey, doc, sig); err != nil {
    return err // refuses bad signatures, non-canonical bytes, oversized documents, and invalid specs
}
decoded, err := contracts.DecodeJobSpec(doc)
if err != nil {
    return err // after a nil Verify this can only be a decode-level refusal (malformed, unknown field, oversized)
}
```

Because `Verify` runs the full validation battery after the signature
check, the verify-then-decode flow above never hands an invalid spec
onward: a document that verifies is by construction a valid spec.

The validation battery refuses a spec that violates a law, with a typed,
machine-readable error naming the rule and the field. For example, a
minimal spec whose image carries a mutable tag:

```json
{"job_id":"job-20260924-000001","run_reference":"acme/payments@main:run-418","attempt":1,"image":"ghcr.io/acme/payments:1.2.3","command":["make","test"],"timeout_seconds":1800,"limits":{"cpu_millicores":4000,"memory_bytes":8589934592,"disk_bytes":68719476736},"egress_allowlist":[],"metering_tags":{}}
```

produces

```
validation failed (rule=digest_only field=image): reference "ghcr.io/acme/payments:1.2.3" is not digest-pinned (no digest anchor); images are pulled only in the form <repository>@sha256:<64 lowercase hex>
```

Consumers match on the `Rule` constant (`contracts.RuleDigestOnly`
here), never on message text.

## The reason vocabulary

Refusals and failures speak a fixed ten-class vocabulary, and each
class maps to the engine disposition it dictates (`DispositionFor`):

| Class                | Disposition      | Meaning                                                    |
|----------------------|------------------|------------------------------------------------------------|
| `quota`              | `fallback`       | The org's admission quota is exhausted; run on Tier P.     |
| `minutes_ceiling`    | `hard_fail`      | The monthly minutes ceiling is reached; no fallback.       |
| `gate`               | `fallback`       | The hosted-runner gate is off for this (org, project).     |
| `no_capacity`        | `fallback`       | Cold provisioning found no capacity.                       |
| `dispatch_failure`   | `fallback`       | The pool could not deliver the job (platform fault).       |
| `platform_timeout`   | `platform_fault` | The watchdog breached a platform deadline.                 |
| `disk_pressure`      | `hard_fail`      | The job exceeded its own declared disk cap.                |
| `customer_config`    | `hard_fail`      | A customer-side configuration failure (no fallback).       |
| `customer_capability`| `fallback`       | The platform removed the capability, not the customer.     |
| `cancelled`          | `cancelled`      | The job was stopped by an authenticated cancel directive.  |

Every reason carries a required human message (`Reason.Validate`).

## The cancel verb

`CancelSpec` is the signed directive that stops a running attempt: the
job's identity (`job_id`, `run_reference`, `attempt` — the job-spec's
own idempotency key) plus the cancellation's `Reason`. The directive
rides the same discipline as the job spec — canonical JSON, a detached
Ed25519 signature made with the SAME engine key that signs job specs, a
strict decoder, and validate-then-sign / validate-then-accept laws:

```go
sig, err := contracts.SignCancel(engineKey, cancelSpec)   // refuses an invalid directive
err = contracts.VerifyCancel(publicKey, doc, sig)         // canonical bytes + signature + battery
directive, err := contracts.DecodeCancelSpec(doc)         // strict decode, unknown fields refused
```

The executor matches the directive's identity against the attempt it is
running; a directive for a job that is not executing is a benign
no-op — the verb is idempotent.

## The machine-side middleman protocol

The agent and the runnermand daemon (the machine's supervised
middleman binary) share their local unix socket protocol through this
module: both import it, so the exact wire definitions exist once and
neither side can drift its copy (the both-import law).

The op set is six verbs — `Prepare`, `MachineFacts`, `RunCleanCycle`,
`Health`, `SampleMetrics`, `TapConsole` — carried as request and reply
documents (`middleman_wire.go`). Every request carries an `Envelope`
(op name, op id, deadline) and every reply a `ReplyHeader` (echoed
identity, accepted or the typed refusal). The laws the wire encodes:

- **The custody law.** `Delivery` carries the verified payload only —
  the start render, the digest pin, the artifacts. The completion
  signing seed is never a field of any document (the strict decoder
  refuses one by name). The registration token crosses only at
  install, inside `fresh_registration_token`, one shot per delivery
  attempt: a Prepare retry is the same delivery identity with
  `delivery_attempt` advanced and a FRESH token.
- **The deadline law.** Every envelope carries `deadline_unix_ms`;
  the daemon answers `deadline-exceeded` by name rather than hanging.
  Health's deadline is short by rule (`MaxHealthDeadline`, enforced by
  the envelope battery), not by comment.
- **The exact-match handshake.** On connect the agent announces the
  protocol version it was built against (`ProtocolVersion`); the
  daemon answers what it implements (`NegotiateHello`). Equal versions
  accept; any other pair refuses loudly with BOTH versions and the
  expected rule named (`HandshakeRefusal`). v1 negotiates no
  compatible range.
- **The typed refusals.** `busy`, `deadline-exceeded`, `unknown-job`,
  `unknown-target`, `controller-displaced`, and `unknown-op` are wire
  documents (refusal.go), never free-form error strings. The
  lifecycle is two verbs: cancel is the forge-side cancel plus one
  RunCleanCycle; resume is Prepare again.

The protocol's golden fixtures live under
`testdata/golden/middleman` (regenerate with
`go test -run "TestGoldenMiddleman|TestGoldenHandshake|TestGoldenRefusal" -update-golden`
only when the wire changes deliberately). The both-import pin
(`TestBothImportPin`) reads the sibling agent checkout's go.mod and
committed vendor tree and fails when the agent's pinned copy declares
a different protocol version than this module.

## Compatibility

The golden wire fixtures under `testdata/golden` pin the exact canonical
bytes of representative documents and their deterministic signatures. A
schema change that moves them fails the test suite, forcing an explicit,
reviewed fixture update (regenerate with
`go test -run TestGoldenWireFixtures -update-golden` only when the wire
contract changes deliberately).

## Development

```sh
go test ./... -count=1   # the module's own battery is the gate
gofmt -l .               # must be empty
go vet ./...             # must be clean
```

CI runs the battery, the formatting and vet checks, the private-import
guard, and the license scan. The private-import guard fails on ANY
`github.com/bare-metal-cloud/` dependency other than
`github.com/bare-metal-cloud/runner-contracts` itself (so runner-pool
and any future private module trip it). The license scan fails if
`go list -m all` reports any module beyond runner-contracts: the module
must stay stdlib-only, and a dependency may land only after a license
review.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Security
issues: see [SECURITY.md](SECURITY.md).
