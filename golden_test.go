package contracts_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// updateGolden regenerates the pinned fixtures under testdata/golden from
// the current schema. Run it ONLY when the wire contract changes
// deliberately: the fixtures are the compatibility contract between the
// engine, the agent, and the Pool Manager across versions.
//
//	go test -run TestGoldenWireFixtures -update-golden
var updateGolden = flag.Bool("update-golden", false, "rewrite the golden wire fixtures from the current schema")

// validFullSpec is the fully-populated valid spec used by the validation
// battery mutations and the full golden fixture.
func validFullSpec() contracts.JobSpec {
	plain := "-count=1"
	secret := "credential-store://payments/ci/database-url"
	return contracts.JobSpec{
		JobID:        "job-20260924-000042",
		RunReference: "acme/payments@main:run-418",
		Attempt:      2,
		Image:        imgRef("ghcr.io/acme/payments-ci", "ab"),
		Command:      []string{"make", "test"},
		Services: []contracts.ServiceContainer{
			{Name: "postgres", Image: imgRef("docker.io/library/postgres", "cd")},
			{Name: "redis", Image: imgRef("docker.io/library/redis", "ef"), Command: []string{"redis-server", "--appendonly", "no"}},
		},
		Build: &contracts.BuildSpec{BaseImage: imgRef("ghcr.io/acme/base", "01")},
		Env: []contracts.EnvEntry{
			{Name: "GOFLAGS", Value: &plain},
			{Name: "DATABASE_URL", SecretReference: &secret},
		},
		ArtifactInputs: []contracts.ArtifactInput{
			{Name: "sbom", Reference: imgRef("ghcr.io/acme/sboms", "23")},
		},
		ArtifactOutputs: []contracts.ArtifactOutput{
			{Name: "app-image", Repository: "registry.acme.example/payments/app", Tags: []string{"ci-418"}},
		},
		TimeoutSeconds: 3600,
		Limits: contracts.ResourceLimits{
			CPUMillicores: 8000,
			MemoryBytes:   16 * GiB,
			DiskBytes:     TiB,
		},
		EgressAllowlist: []string{"registry.acme.example", "github.com", "proxy.golang.org"},
		MeteringTags:    map[string]string{"org": "acme", "project": "payments", "pipeline": "payments-ci"},
	}
}

// validBuildSpec is the fully-populated BuildJobSpec-class fixture: the
// git-source build a dispatch composes (the source ref, the resolved
// plan, the push target, the credential REFERENCES, the log topic).
func validBuildSpec() contracts.JobSpec {
	srcRef := "credential-store://build/acme-platform-source-pull" //nolint:gosec // a reference, not a credential
	pushRef := "credential-store://build/acme-app-registry-push"
	return contracts.JobSpec{
		JobID:        "bld-9f1c2a3e-4b5d-4e6f-8a9b-0c1d2e3f4a5b",
		RunReference: "acme/payments@main:build-run-418",
		Attempt:      2,
		Source: &contracts.SourceRef{
			Repo:   "https://git.acme.example/acme/platform.git",
			Commit: sha256hex("cc"),
		},
		Image:          imgRef("ghcr.io/acme/builder", "de"),
		Command:        []string{"buildkit-render"},
		TimeoutSeconds: 7200,
		Build: &contracts.BuildSpec{
			BaseImage:              imgRef("ghcr.io/acme/builder", "de"),
			Strategy:               "plan",
			Runtime:                "node:22",
			Install:                "npm ci",
			Build:                  "npm run build",
			Start:                  "npm start",
			Port:                   3000,
			SourcePullCredential:   srcRef,
			RegistryPushCredential: pushRef,
		},
		ArtifactOutputs: []contracts.ArtifactOutput{
			{Name: "app-image", Repository: "registry.acme.example/payments/app", Tags: []string{"rev-418"}},
		},
		Limits: contracts.ResourceLimits{
			CPUMillicores: 8000,
			MemoryBytes:   16 * GiB,
			DiskBytes:     TiB,
		},
		EgressAllowlist: []string{"registry.acme.example", "git.acme.example"},
		MeteringTags:    map[string]string{"org": "acme", "project": "payments", "kind": "build"},
		LogTopicID:      "org-1-build-run-418",
	}
}

// goldenFixtures maps fixture names to the specs they pin.
func goldenFixtures() map[string]contracts.JobSpec {
	return map[string]contracts.JobSpec{
		"minimal-job":           validMinimalSpec(),
		"full-job":              validFullSpec(),
		"build-job":             validBuildSpec(),
		"tierv-convergence-job": tierVConvergenceSpec(),
	}
}

// TestGoldenWireFixtures pins the wire contract. Each fixture under
// testdata/golden must (1) be exactly the canonical encoding of its spec,
// (2) carry the Ed25519 signature of the pinned test key over those bytes
// (signatures are deterministic, so both drift together), and (3) verify
// and decode back to identical content. A schema change that alters any
// of these fails here, forcing an explicit fixture update.
func TestGoldenWireFixtures(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)

	for name, spec := range goldenFixtures() {
		t.Run(name, func(t *testing.T) {
			jsonPath := filepath.Join("testdata", "golden", name+".json")
			sigPath := filepath.Join("testdata", "golden", name+".sig")

			canonical, err := contracts.CanonicalJSON(spec)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			sig, err := contracts.Sign(key, spec)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if *updateGolden {
				if err := os.WriteFile(jsonPath, canonical, 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
				encoded := base64.StdEncoding.EncodeToString(sig) + "\n"
				if err := os.WriteFile(sigPath, []byte(encoded), 0o644); err != nil {
					t.Fatalf("write signature: %v", err)
				}
				return
			}

			pinned, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatalf("read pinned fixture (run with -update-golden after a deliberate wire change): %v", err)
			}
			if !bytes.Equal(canonical, pinned) {
				t.Fatalf("canonical encoding drifted from the pinned fixture:\n pinned: %s\n current: %s", pinned, canonical)
			}

			raw, err := os.ReadFile(sigPath)
			if err != nil {
				t.Fatalf("read pinned signature: %v", err)
			}
			pinnedSig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
			if err != nil {
				t.Fatalf("pinned signature is not base64: %v", err)
			}
			if !bytes.Equal(sig, pinnedSig) {
				t.Fatalf("signature over the pinned document changed (key or canonical form drifted)")
			}

			if err := contracts.Verify(pub, pinned, pinnedSig); err != nil {
				t.Fatalf("pinned fixture no longer verifies: %v", err)
			}
			decoded, err := contracts.DecodeJobSpec(pinned)
			if err != nil {
				t.Fatalf("pinned fixture no longer decodes: %v", err)
			}
			recanonical, err := contracts.CanonicalJSON(decoded)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			if !bytes.Equal(recanonical, pinned) {
				t.Fatalf("decoded fixture re-encodes differently:\n pinned: %s\n decoded: %s", pinned, recanonical)
			}
		})
	}
}

// TestReorderedJSONDecodesToIdenticalSpec proves the decode half of the
// wire contract: a document whose JSON keys appear in a different order
// (for example produced by a non-Go consumer) decodes to a spec whose
// canonical encoding matches the pinned fixture. Wire compatibility is
// about content; canonical form is only mandatory where signatures live.
func TestReorderedJSONDecodesToIdenticalSpec(t *testing.T) {
	pinned, err := os.ReadFile(filepath.Join("testdata", "golden", "full-job.json"))
	if err != nil {
		t.Fatalf("read pinned fixture: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(pinned, &generic); err != nil {
		t.Fatalf("pinned fixture is not JSON: %v", err)
	}
	reordered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if bytes.Equal(pinned, reordered) {
		t.Fatal("test is broken: the two wire forms are byte-identical, so nothing is proven")
	}

	spec, err := contracts.DecodeJobSpec(reordered)
	if err != nil {
		t.Fatalf("reordered document refused: %v", err)
	}
	canonical, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !bytes.Equal(canonical, pinned) {
		t.Fatalf("reordered document decoded to different content:\n pinned: %s\n decoded: %s", pinned, canonical)
	}
}
