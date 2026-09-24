package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// tierVConvergenceSpec is a Tier-V-shaped job document: the job-spec the
// in-cluster engine (Epic 145.5) hands a node-host agent for a pipeline
// step, shaped per the Epic 145 plan's step vocabulary — the `run` step
// (image + command), `service` sibling test containers, the `build` step
// (base image), and the `push` side (artifact outputs, whose output tags
// are applied to the customer's registry on push; output tags are
// deliberately exempt from the digest-only law because they are applied
// at push time, never used to pull).
//
// There is no `deploy` field: deploy is handed to the reconciler and the
// pool NEVER deploys (the never-deploys law), so the runner job-spec
// deliberately cannot express it. The built digest flows to deploy
// through artifact outputs.
//
// This is the one-schema convergence fixture (Q2): the Tier V and Tier H
// job documents are the same schema with two trust anchors.
func tierVConvergenceSpec() contracts.JobSpec {
	plain := "unix:///var/run/buildkit/buildkitd.sock"
	secret := "credential-store://payments/ci/registry-pull"
	return contracts.JobSpec{
		JobID:        "job-20260924-000418",
		RunReference: "acme/payments@main:run-418",
		Attempt:      1,
		Image:        imgRef("ghcr.io/acme/payments-builder", "ab"),
		Command:      []string{"buildctl", "build", "--output", "type=oci"},

		Services: []contracts.ServiceContainer{
			{Name: "postgres", Image: imgRef("docker.io/library/postgres", "cd"), Command: []string{"postgres", "-c", "fsync=off"}},
			{Name: "redis", Image: imgRef("docker.io/library/redis", "ef")},
		},

		Build: &contracts.BuildSpec{BaseImage: imgRef("ghcr.io/acme/runtime-base", "01")},

		Env: []contracts.EnvEntry{
			{Name: "BUILDKIT_HOST", Value: &plain},
			{Name: "REGISTRY_PULL_TOKEN", SecretReference: &secret},
		},

		ArtifactInputs: []contracts.ArtifactInput{
			{Name: "runtime-base-lock", Reference: imgRef("ghcr.io/acme/locks", "23")},
		},
		ArtifactOutputs: []contracts.ArtifactOutput{
			{
				Name:       "app-image",
				Repository: "registry.acme.example/payments/app",
				Tags:       []string{"ci-418", "sha-9f1c2e"},
			},
		},

		TimeoutSeconds: 5400,
		Limits: contracts.ResourceLimits{
			CPUMillicores: 12000,
			MemoryBytes:   32 * GiB,
			DiskBytes:     2 * TiB,
		},

		EgressAllowlist: []string{
			"registry.acme.example",
			"github.com",
			"proxy.golang.org",
			"storage.googleapis.com",
		},

		MeteringTags: map[string]string{
			"org":      "acme",
			"project":  "payments",
			"pipeline": "payments-ci",
			"runner":   "node",
		},
	}
}

// TestOneSchemaConvergence proves the Q2 ruling in code: the Tier-V-shaped
// job document validates against this module's schema (the ONE schema),
// and it works under BOTH trust anchors — the engine trust material
// delivered with the bundle install (Tier V) and the control-plane
// channel (Tier H, with the engine's signature retained for provenance).
// The schema is anchor-agnostic: whatever Ed25519 public key verifies the
// document, the document is the same document.
func TestOneSchemaConvergence(t *testing.T) {
	spec := tierVConvergenceSpec()

	if errs := contracts.Validate(spec); len(errs) != 0 {
		t.Fatalf("the Tier-V-shaped job document does not validate against the module schema: %v", errs)
	}

	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}

	// Trust anchor 1 (Tier V): the engine key from the bundle-delivered
	// trust material (pinned test seed stands in for it).
	engineKey := loadTestEngineKey(t)
	enginePub := engineKey.Public().(ed25519.PublicKey)
	engineSig, err := contracts.Sign(engineKey, spec)
	if err != nil {
		t.Fatalf("engine anchor sign: %v", err)
	}

	// Trust anchor 2 (Tier H): the control-plane channel's own key.
	cpSeed := make([]byte, ed25519.SeedSize)
	for i := range cpSeed {
		cpSeed[i] = byte(0xC0 ^ (i*7 + 1))
	}
	cpKey := ed25519.NewKeyFromSeed(cpSeed)
	cpPub := cpKey.Public().(ed25519.PublicKey)
	cpSig, err := contracts.Sign(cpKey, spec)
	if err != nil {
		t.Fatalf("control-plane anchor sign: %v", err)
	}

	if err := contracts.Verify(enginePub, doc, engineSig); err != nil {
		t.Fatalf("Tier V anchor verification failed: %v", err)
	}
	if err := contracts.Verify(cpPub, doc, cpSig); err != nil {
		t.Fatalf("Tier H anchor verification failed: %v", err)
	}
	if err := contracts.Verify(enginePub, doc, cpSig); err == nil {
		t.Fatal("a signature from the wrong anchor verified; anchors are distinct keys")
	}

	// Both anchors decode identical content from the same wire bytes.
	decoded, err := contracts.DecodeJobSpec(doc)
	if err != nil {
		t.Fatalf("DecodeJobSpec: %v", err)
	}
	recanonical, err := contracts.CanonicalJSON(decoded)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !bytes.Equal(recanonical, doc) {
		t.Fatal("the converged document does not round-trip byte-identically")
	}
}
