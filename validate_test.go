package contracts_test

import (
	"fmt"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// validate returns the validation errors for spec, failing the test only
// when the error is not a typed ValidationErrors value.
func validate(t *testing.T, spec contracts.JobSpec) contracts.ValidationErrors {
	t.Helper()
	errs := contracts.Validate(spec)
	return errs
}

// wantRule asserts that errs contains an error with the given rule and
// field, and returns the matching error.
func wantRule(t *testing.T, errs contracts.ValidationErrors, rule, field string) contracts.ValidationError {
	t.Helper()
	for _, e := range errs {
		if e.Rule == rule && e.Field == field {
			return e
		}
	}
	t.Fatalf("no error with rule=%s field=%s in %v", rule, field, errs)
	return contracts.ValidationError{}
}

// TestDigestOnlyRefusalsAcrossEveryImageBearingField pins the digest-only
// law for all four image-bearing fields of the schema: the run image, the
// service container images, the build base image, and the artifact input
// references. A mutable tag, the latest tag, a bare repository, a short
// digest, a foreign digest algorithm, and an uppercase digest all refuse.
func TestDigestOnlyRefusalsAcrossEveryImageBearingField(t *testing.T) {
	cases := []struct {
		name  string
		mutbl func(spec contracts.JobSpec) contracts.JobSpec
		field string
		ref   string
	}{
		{
			name:  "run image with mutable tag",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec { s.Image = "ghcr.io/acme/payments:1.2.3"; return s },
			field: "image",
			ref:   "ghcr.io/acme/payments:1.2.3",
		},
		{
			name:  "run image with latest",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec { s.Image = "ghcr.io/acme/payments:latest"; return s },
			field: "image",
			ref:   "ghcr.io/acme/payments:latest",
		},
		{
			name:  "run image bare repository",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec { s.Image = "ghcr.io/acme/payments"; return s },
			field: "image",
			ref:   "ghcr.io/acme/payments",
		},
		{
			name:  "run image with short digest",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec { s.Image = "ghcr.io/acme/payments@sha256:abcd"; return s },
			field: "image",
			ref:   "ghcr.io/acme/payments@sha256:abcd",
		},
		{
			name: "run image with md5 digest",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec {
				s.Image = "ghcr.io/acme/payments@md5:" + sha256hex("ab")
				return s
			},
			field: "image",
			ref:   "ghcr.io/acme/payments@md5:" + sha256hex("ab"),
		},
		{
			name: "run image with uppercase digest",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec {
				s.Image = "ghcr.io/acme/payments@sha256:" + strings.ToUpper(sha256hex("ab"))
				return s
			},
			field: "image",
			ref:   "ghcr.io/acme/payments@sha256:" + strings.ToUpper(sha256hex("ab")),
		},
		{
			name: "service container image with mutable tag",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec {
				s.Services[0].Image = "docker.io/library/postgres:16"
				return s
			},
			field: "services[0].image",
			ref:   "docker.io/library/postgres:16",
		},
		{
			name: "service container image with latest",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec {
				s.Services[1].Image = "docker.io/library/redis:latest"
				return s
			},
			field: "services[1].image",
			ref:   "docker.io/library/redis:latest",
		},
		{
			name:  "build base image with mutable tag",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec { s.Build.BaseImage = "ghcr.io/acme/base:3.1"; return s },
			field: "build.base_image",
			ref:   "ghcr.io/acme/base:3.1",
		},
		{
			name: "artifact input with mutable tag",
			mutbl: func(s contracts.JobSpec) contracts.JobSpec {
				s.ArtifactInputs[0].Reference = "ghcr.io/acme/sboms:nightly"
				return s
			},
			field: "artifact_inputs[0].reference",
			ref:   "ghcr.io/acme/sboms:nightly",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validate(t, validFullSpecWithMutations(tc.mutbl))
			e := wantRule(t, errs, contracts.RuleDigestOnly, tc.field)
			if !strings.Contains(e.Message, tc.ref) {
				t.Fatalf("digest_only error does not name the offending reference %q: %s", tc.ref, e.Message)
			}
		})
	}
}

// validFullSpecWithMutations applies mutation to a valid fully-populated
// spec (the same one the golden fixtures pin).
func validFullSpecWithMutations(mutate func(contracts.JobSpec) contracts.JobSpec) contracts.JobSpec {
	return mutate(validFullSpec())
}

func TestDigestOnlyAcceptsCanonicalDigestForm(t *testing.T) {
	errs := validate(t, validFullSpec())
	if len(errs) != 0 {
		t.Fatalf("valid full spec refused: %v", errs)
	}
}

func TestEmptyAllowlistIsLegalDenyAll(t *testing.T) {
	spec := validMinimalSpec() // EgressAllowlist is empty
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("an empty egress allowlist is legal (deny-all); refused with: %v", errs)
	}
	if contracts.AllowlistMatches(spec.EgressAllowlist, "registry.example.com") {
		t.Fatal("empty allowlist matched a host; an empty allowlist means deny-all")
	}
	if contracts.AllowlistMatches(nil, "anything.example") {
		t.Fatal("nil allowlist matched a host; an absent allowlist means deny-all")
	}
}

func TestEgressSuffixMatching(t *testing.T) {
	rules := []string{"registry.acme.example", "github.com"}
	cases := []struct {
		host  string
		match bool
	}{
		{"registry.acme.example", true},           // exact host
		{"blob.registry.acme.example", true},      // subdomain of the suffix
		{"deep.blob.registry.acme.example", true}, // deep subdomain
		{"evilregistry.acme.example", false},      // no partial-label suffix match
		{"registry.acme.example.evil.io", false},  // suffix is not a prefix of the host tail
		{"github.com", true},                      // exact
		{"objects.github.com", true},              // subdomain
		{"notgithub.com", false},                  // no partial-label match
		{"example.org", false},                    // unrelated
		{"Registry.Acme.Example", true},           // host case is insignificant
	}
	for _, tc := range cases {
		if got := contracts.AllowlistMatches(rules, tc.host); got != tc.match {
			t.Errorf("AllowlistMatches(%q, %q) = %v, want %v", rules, tc.host, got, tc.match)
		}
	}
}

func TestEgressEntryValidation(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
	}{
		{"empty entry", ""},
		{"uppercase entry", "Registry.Acme.Example"},
		{"leading dot", ".acme.example"},
		{"trailing dot", "acme.example."},
		{"bare single label", "localhost"},
		{"empty label", "acme..example"},
		{"leading hyphen", "-acme.example"},
		{"scheme smuggled in", "https://acme.example"},
		{"path smuggled in", "acme.example/registry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validMinimalSpec()
			spec.EgressAllowlist = []string{tc.suffix}
			errs := validate(t, spec)
			wantRule(t, errs, contracts.RuleEgressSuffix, "egress_allowlist[0]")
		})
	}
}

func TestLimitsSanity(t *testing.T) {
	base := validMinimalSpec()
	cases := []struct {
		name  string
		field string
		mutbl func(l *contracts.ResourceLimits)
		rule  string
	}{
		{"zero cpu", "limits.cpu_millicores", func(l *contracts.ResourceLimits) { l.CPUMillicores = 0 }, contracts.RuleLimitsPositive},
		{"negative cpu", "limits.cpu_millicores", func(l *contracts.ResourceLimits) { l.CPUMillicores = -1 }, contracts.RuleLimitsPositive},
		{"cpu over maximum", "limits.cpu_millicores", func(l *contracts.ResourceLimits) { l.CPUMillicores = contracts.MaxCPUMillicores + 1 }, contracts.RuleLimitsBounded},
		{"zero memory", "limits.memory_bytes", func(l *contracts.ResourceLimits) { l.MemoryBytes = 0 }, contracts.RuleLimitsPositive},
		{"negative memory", "limits.memory_bytes", func(l *contracts.ResourceLimits) { l.MemoryBytes = -1024 }, contracts.RuleLimitsPositive},
		{"memory over maximum", "limits.memory_bytes", func(l *contracts.ResourceLimits) { l.MemoryBytes = contracts.MaxMemoryBytes + 1 }, contracts.RuleLimitsBounded},
		{"zero disk", "limits.disk_bytes", func(l *contracts.ResourceLimits) { l.DiskBytes = 0 }, contracts.RuleLimitsPositive},
		{"negative disk", "limits.disk_bytes", func(l *contracts.ResourceLimits) { l.DiskBytes = -1 }, contracts.RuleLimitsPositive},
		{"disk over maximum", "limits.disk_bytes", func(l *contracts.ResourceLimits) { l.DiskBytes = contracts.MaxDiskBytes + 1 }, contracts.RuleLimitsBounded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			tc.mutbl(&spec.Limits)
			errs := validate(t, spec)
			wantRule(t, errs, tc.rule, tc.field)
		})
	}
}

func TestLimitsBoundariesAccepted(t *testing.T) {
	spec := validMinimalSpec()
	spec.Limits = contracts.ResourceLimits{
		CPUMillicores: contracts.MaxCPUMillicores,
		MemoryBytes:   contracts.MaxMemoryBytes,
		DiskBytes:     contracts.MaxDiskBytes,
	}
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("maximum boundary limits refused: %v", errs)
	}
	spec.Limits = contracts.ResourceLimits{
		CPUMillicores: contracts.MinCPUMillicores,
		MemoryBytes:   contracts.MinMemoryBytes,
		DiskBytes:     contracts.MinDiskBytes,
	}
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("minimum boundary limits refused: %v", errs)
	}
}

func TestTimeoutBounds(t *testing.T) {
	spec := validMinimalSpec()
	spec.TimeoutSeconds = 0
	wantRule(t, validate(t, spec), contracts.RuleTimeout, "timeout_seconds")

	spec.TimeoutSeconds = -5
	wantRule(t, validate(t, spec), contracts.RuleTimeout, "timeout_seconds")

	spec.TimeoutSeconds = contracts.MaxTimeoutSeconds + 1
	wantRule(t, validate(t, spec), contracts.RuleTimeout, "timeout_seconds")

	spec.TimeoutSeconds = contracts.MaxTimeoutSeconds
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("maximum timeout refused: %v", errs)
	}
}

func TestMeteringTagConstraints(t *testing.T) {
	spec := validMinimalSpec()
	spec.MeteringTags = map[string]string{"Org": "acme"}
	wantRule(t, validate(t, spec), contracts.RuleTagKey, "metering_tags[Org]")

	spec.MeteringTags = map[string]string{"bad key!": "acme"}
	wantRule(t, validate(t, spec), contracts.RuleTagKey, "metering_tags[bad key!]")

	spec.MeteringTags = map[string]string{strings.Repeat("k", contracts.MaxMeteringTagKeyLength+1): "v"}
	wantRule(t, validate(t, spec), contracts.RuleTagKey, "metering_tags["+strings.Repeat("k", contracts.MaxMeteringTagKeyLength+1)+"]")

	spec.MeteringTags = map[string]string{"ok": strings.Repeat("v", contracts.MaxMeteringTagValueLength+1)}
	wantRule(t, validate(t, spec), contracts.RuleTagValue, "metering_tags[ok]")

	tooMany := map[string]string{}
	for i := 0; i <= contracts.MaxMeteringTags; i++ {
		tooMany[fmt.Sprintf("tag%03d", i)] = "v"
	}
	spec.MeteringTags = tooMany
	wantRule(t, validate(t, spec), contracts.RuleTagCount, "metering_tags")

	spec.MeteringTags = map[string]string{}
	for i := 0; i < contracts.MaxMeteringTags; i++ {
		spec.MeteringTags[fmt.Sprintf("tag%03d", i)] = "v"
	}
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("exactly MaxMeteringTags tags refused: %v", errs)
	}
}

func TestSecretReferenceShape(t *testing.T) {
	bad := []struct {
		name string
		ref  string
	}{
		{"missing credential-store scheme", "vault/payments/database-url"},
		{"empty key path", "credential-store://"},
		{"path traversal", "credential-store://payments/../../etc/passwd"},
		{"whitespace in path", "credential-store://payments/ci database-url"},
		{"uppercase scheme", "Credential-Store://payments/db"},
		{"inline secret", "credential-store://s3cr3t-P4ssw0rd"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			spec := validFullSpec()
			ref := tc.ref
			spec.Env[1].SecretReference = &ref
			errs := validate(t, spec)
			wantRule(t, errs, contracts.RuleSecretReference, "env[1].secret_reference")
		})
	}
}

func TestSecretReferenceAcceptsCredentialStoreNamespace(t *testing.T) {
	spec := validFullSpec()
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("credential-store reference refused: %v", errs)
	}
}

func TestEnvEntryValidation(t *testing.T) {
	t.Run("bad name", func(t *testing.T) {
		spec := validMinimalSpec()
		v := "x"
		spec.Env = []contracts.EnvEntry{{Name: "1BAD-NAME", Value: &v}}
		wantRule(t, validate(t, spec), contracts.RuleEnvName, "env[0].name")
	})
	t.Run("duplicate name", func(t *testing.T) {
		spec := validMinimalSpec()
		v := "x"
		spec.Env = []contracts.EnvEntry{{Name: "GOFLAGS", Value: &v}, {Name: "GOFLAGS", Value: &v}}
		wantRule(t, validate(t, spec), contracts.RuleEnvDuplicate, "env[1].name")
	})
	t.Run("both value and secret reference", func(t *testing.T) {
		spec := validMinimalSpec()
		v, s := "x", "credential-store://a/b"
		spec.Env = []contracts.EnvEntry{{Name: "TOKEN", Value: &v, SecretReference: &s}}
		wantRule(t, validate(t, spec), contracts.RuleEnvConflict, "env[0]")
	})
	t.Run("neither value nor secret reference", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.Env = []contracts.EnvEntry{{Name: "TOKEN"}}
		wantRule(t, validate(t, spec), contracts.RuleEnvRequired, "env[0]")
	})
	t.Run("too many entries", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.Env = nil
		for i := 0; i <= contracts.MaxEnvEntries; i++ {
			value := "x"
			spec.Env = append(spec.Env, contracts.EnvEntry{
				Name:  fmt.Sprintf("VAR_%03d", i),
				Value: &value,
			})
		}
		wantRule(t, validate(t, spec), contracts.RuleEnvCount, "env")
	})
}

func TestServiceConstraints(t *testing.T) {
	t.Run("duplicate service name", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[1].Name = spec.Services[0].Name
		wantRule(t, validate(t, spec), contracts.RuleServiceDuplicate, "services[1].name")
	})
	t.Run("bad service name", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Name = "Postgres_Main"
		wantRule(t, validate(t, spec), contracts.RuleServiceName, "services[0].name")
	})
	t.Run("too many services", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services = nil
		for i := 0; i <= contracts.MaxServices; i++ {
			spec.Services = append(spec.Services, contracts.ServiceContainer{
				Name:  fmt.Sprintf("svc%03d", i),
				Image: imgRef("ghcr.io/acme/svc", "ef"),
			})
		}
		wantRule(t, validate(t, spec), contracts.RuleServiceCount, "services")
	})
	t.Run("empty command entry", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Command = []string{"redis-server", ""}
		wantRule(t, validate(t, spec), contracts.RuleCommand, "services[0].command[1]")
	})
}

func TestCommandConstraints(t *testing.T) {
	spec := validMinimalSpec()
	spec.Command = nil
	wantRule(t, validate(t, spec), contracts.RuleRequired, "command")

	spec.Command = []string{"make", ""}
	wantRule(t, validate(t, spec), contracts.RuleCommand, "command[1]")
}

func TestRequiredAndShapeRefusals(t *testing.T) {
	t.Run("empty job_id", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.JobID = ""
		wantRule(t, validate(t, spec), contracts.RuleRequired, "job_id")
	})
	t.Run("bad job_id charset", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.JobID = "job id with spaces"
		wantRule(t, validate(t, spec), contracts.RuleJobID, "job_id")
	})
	t.Run("empty run_reference", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.RunReference = ""
		wantRule(t, validate(t, spec), contracts.RuleRequired, "run_reference")
	})
	t.Run("attempt below one", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.Attempt = 0
		wantRule(t, validate(t, spec), contracts.RuleAttempt, "attempt")
	})
	t.Run("empty image", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.Image = ""
		wantRule(t, validate(t, spec), contracts.RuleRequired, "image")
	})
}

// TestNameLengthCapRefusals pins the 63-character cap the messages have
// always claimed: service names, artifact-input names, and artifact-
// output names longer than MaxNameLength refuse with their name rule.
func TestNameLengthCapRefusals(t *testing.T) {
	long := strings.Repeat("n", 100)
	edge := strings.Repeat("n", contracts.MaxNameLength)
	over := strings.Repeat("n", contracts.MaxNameLength+1)

	t.Run("service name far over the cap", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Name = long
		wantRule(t, validate(t, spec), contracts.RuleServiceName, "services[0].name")
	})
	t.Run("service name one over the cap", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Name = over
		wantRule(t, validate(t, spec), contracts.RuleServiceName, "services[0].name")
	})
	t.Run("service name at the cap is accepted", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Name = edge
		if errs := validate(t, spec); len(errs) != 0 {
			t.Fatalf("a %d-character service name refused: %v", contracts.MaxNameLength, errs)
		}
	})
	t.Run("artifact input name over the cap", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactInputs[0].Name = long
		wantRule(t, validate(t, spec), contracts.RuleArtifactName, "artifact_inputs[0].name")
	})
	t.Run("artifact output name over the cap", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Name = long
		wantRule(t, validate(t, spec), contracts.RuleArtifactName, "artifact_outputs[0].name")
	})
}

// TestEgressCountBound pins MaxEgressEntries: the allowlist is a bounded
// list, not an unbounded bag of suffixes.
func TestEgressCountBound(t *testing.T) {
	spec := validMinimalSpec()
	spec.EgressAllowlist = nil
	for i := 0; i <= contracts.MaxEgressEntries; i++ {
		spec.EgressAllowlist = append(spec.EgressAllowlist, fmt.Sprintf("svc%02d.acme.example", i))
	}
	wantRule(t, validate(t, spec), contracts.RuleEgressCount, "egress_allowlist")

	spec.EgressAllowlist = spec.EgressAllowlist[:contracts.MaxEgressEntries]
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("exactly MaxEgressEntries allowlist entries refused: %v", errs)
	}
}

// TestCommandArgsBound pins MaxCommandArgs for the job's own argv and
// for every service container's argv.
func TestCommandArgsBound(t *testing.T) {
	t.Run("job command", func(t *testing.T) {
		spec := validMinimalSpec()
		spec.Command = nil
		for i := 0; i <= contracts.MaxCommandArgs; i++ {
			spec.Command = append(spec.Command, fmt.Sprintf("arg%03d", i))
		}
		wantRule(t, validate(t, spec), contracts.RuleCommandCount, "command")

		spec.Command = spec.Command[:contracts.MaxCommandArgs]
		if errs := validate(t, spec); len(errs) != 0 {
			t.Fatalf("exactly MaxCommandArgs argv entries refused: %v", errs)
		}
	})
	t.Run("service command", func(t *testing.T) {
		spec := validFullSpec()
		spec.Services[0].Command = nil
		for i := 0; i <= contracts.MaxCommandArgs; i++ {
			spec.Services[0].Command = append(spec.Services[0].Command, fmt.Sprintf("arg%03d", i))
		}
		wantRule(t, validate(t, spec), contracts.RuleCommandCount, "services[0].command")
	})
}

// TestOutputTagsBound pins MaxOutputTags: the push-time tag set per
// artifact output is bounded.
func TestOutputTagsBound(t *testing.T) {
	spec := validFullSpec()
	spec.ArtifactOutputs[0].Tags = nil
	for i := 0; i <= contracts.MaxOutputTags; i++ {
		spec.ArtifactOutputs[0].Tags = append(spec.ArtifactOutputs[0].Tags, fmt.Sprintf("tag%02d", i))
	}
	wantRule(t, validate(t, spec), contracts.RuleOutputTagCount, "artifact_outputs[0].tags")

	spec.ArtifactOutputs[0].Tags = spec.ArtifactOutputs[0].Tags[:contracts.MaxOutputTags]
	if errs := validate(t, spec); len(errs) != 0 {
		t.Fatalf("exactly MaxOutputTags tags refused: %v", errs)
	}
}

// TestArtifactNameDedupe extends the dedupe law (env names, service
// names) to artifact-input and artifact-output names: within one list,
// a name may be used exactly once.
func TestArtifactNameDedupe(t *testing.T) {
	t.Run("duplicate input names", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactInputs = append(spec.ArtifactInputs, contracts.ArtifactInput{
			Name:      spec.ArtifactInputs[0].Name,
			Reference: imgRef("ghcr.io/acme/sboms", "45"),
		})
		wantRule(t, validate(t, spec), contracts.RuleArtifactDuplicate, "artifact_inputs[1].name")
	})
	t.Run("duplicate output names", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs = append(spec.ArtifactOutputs, contracts.ArtifactOutput{
			Name:       spec.ArtifactOutputs[0].Name,
			Repository: "registry.acme.example/payments/app-2",
		})
		wantRule(t, validate(t, spec), contracts.RuleArtifactDuplicate, "artifact_outputs[1].name")
	})
}

func TestArtifactOutputValidation(t *testing.T) {
	t.Run("repository carries a tag", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "registry.acme.example/payments/app:ci-418"
		wantRule(t, validate(t, spec), contracts.RuleOCIRepository, "artifact_outputs[0].repository")
	})
	t.Run("repository carries a digest", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "registry.acme.example/payments/app@sha256:" + sha256hex("ab")
		wantRule(t, validate(t, spec), contracts.RuleOCIRepository, "artifact_outputs[0].repository")
	})
	t.Run("host:port anchor composes (the 2026-10-08 drill's push target)", func(t *testing.T) {
		// The platform composes the declared registry row's URL host
		// (with port) onto a bare push repository; the battery accepts
		// the composed form the machine's driver then pushes.
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "169.58.14.139:5000/drill01"
		if got := validate(t, spec); len(got) != 0 {
			t.Fatalf("the composed host:port/repository push target must validate, got: %v", got)
		}
	})
	t.Run("host anchor without a port composes", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "169.58.14.139/drill01"
		if got := validate(t, spec); len(got) != 0 {
			t.Fatalf("the host/repository push target must validate, got: %v", got)
		}
	})
	t.Run("port without a repository path is refused", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "169.58.14.139:5000"
		wantRule(t, validate(t, spec), contracts.RuleOCIRepository, "artifact_outputs[0].repository")
	})
	t.Run("a tag after the host segment is refused", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Repository = "registry.acme.example/payments/app:latest/drill01"
		wantRule(t, validate(t, spec), contracts.RuleOCIRepository, "artifact_outputs[0].repository")
	})
	t.Run("bad output tag", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs[0].Tags = []string{"-leading-hyphen"}
		wantRule(t, validate(t, spec), contracts.RuleOutputTag, "artifact_outputs[0].tags[0]")
	})
	t.Run("too many outputs", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactOutputs = nil
		for i := 0; i <= contracts.MaxArtifactOutputs; i++ {
			spec.ArtifactOutputs = append(spec.ArtifactOutputs, contracts.ArtifactOutput{
				Name:       fmt.Sprintf("out%03d", i),
				Repository: fmt.Sprintf("registry.acme.example/payments/out%03d", i),
			})
		}
		wantRule(t, validate(t, spec), contracts.RuleArtifactCount, "artifact_outputs")
	})
}

func TestArtifactInputValidation(t *testing.T) {
	t.Run("too many inputs", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactInputs = nil
		for i := 0; i <= contracts.MaxArtifactInputs; i++ {
			spec.ArtifactInputs = append(spec.ArtifactInputs, contracts.ArtifactInput{
				Name:      fmt.Sprintf("in%03d", i),
				Reference: imgRef("ghcr.io/acme/in", "cd"),
			})
		}
		wantRule(t, validate(t, spec), contracts.RuleArtifactCount, "artifact_inputs")
	})
	t.Run("bad input name", func(t *testing.T) {
		spec := validFullSpec()
		spec.ArtifactInputs[0].Name = "bad name"
		wantRule(t, validate(t, spec), contracts.RuleArtifactName, "artifact_inputs[0].name")
	})
}
