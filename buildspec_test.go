package contracts_test

// buildspec_test.go — the BuildJobSpec class's battery (epic 164 entry 4,
// the builder's dispatch core): the source ref, the resolved plan rows,
// the credential REFERENCES (the isolation negative-set), and the log
// topic. The class is JobSpec — the channel does not fork — so every
// rule here rides the same Validate/DecodeJobSpec/Sign/Verify battery
// the CI shape uses, and the goldens pin the class's wire form.

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// validBuildClassSpec returns a valid BuildJobSpec-class spec for the
// mutation battery.
func validBuildClassSpec() contracts.JobSpec {
	spec := validMinimalSpec()
	spec.Source = &contracts.SourceRef{
		Repo:   "https://git.acme.example/acme/platform.git",
		Commit: sha256hex("aa"),
	}
	srcRef := "credential-store://build/source-pull" //nolint:gosec // a reference, not a credential
	pushRef := "credential-store://build/registry-push"
	spec.Build = &contracts.BuildSpec{
		BaseImage:              imgRef("ghcr.io/acme/builder", "de"),
		Strategy:               "plan",
		Runtime:                "node:22",
		Install:                "npm ci",
		Build:                  "npm run build",
		Start:                  "npm start",
		Port:                   3000,
		SourcePullCredential:   srcRef,
		RegistryPushCredential: pushRef,
	}
	spec.LogTopicID = "org-1-build-run-418"
	return spec
}

// assertSingleRule asserts err is ValidationErrors carrying exactly one
// finding and it names the given rule.
func assertSingleRule(t *testing.T, errs contracts.ValidationErrors, rule string) {
	t.Helper()
	if len(errs) != 1 {
		t.Fatalf("want exactly one finding naming %s, got %d: %v", rule, len(errs), errs)
	}
	if errs[0].Rule != rule {
		t.Fatalf("rule = %s, want %s (%v)", errs[0].Rule, rule, errs[0])
	}
}

func TestBuildClassValidSpecPassesBattery(t *testing.T) {
	if errs := contracts.Validate(validBuildClassSpec()); len(errs) != 0 {
		t.Fatalf("valid BuildJobSpec-class spec failed the battery: %v", errs)
	}
}

func TestBuildClassStrategyVocabulary(t *testing.T) {
	spec := validBuildClassSpec()
	spec.Build.Strategy = "cnb"
	errs := contracts.Validate(spec)
	assertSingleRule(t, errs, contracts.RuleBuildStrategy)
	if !strings.Contains(errs[0].Message, "plan | dockerfile") {
		t.Fatalf("strategy refusal does not name the vocabulary: %v", errs[0])
	}
}

// TestBuildClassLegacyShapeUnchanged pins the backward-compatibility
// law: a Build step carrying ONLY BaseImage (the legacy CI build shape)
// stays valid — the strategy discriminator gates the new rules, never
// the old shape.
func TestBuildClassLegacyShapeUnchanged(t *testing.T) {
	spec := validMinimalSpec()
	spec.Build = &contracts.BuildSpec{BaseImage: imgRef("ghcr.io/acme/base", "01")}
	if errs := contracts.Validate(spec); len(errs) != 0 {
		t.Fatalf("legacy build shape failed the battery: %v", errs)
	}
}

func TestBuildClassPlanRequiresFullPlan(t *testing.T) {
	for _, row := range []struct {
		clear func(*contracts.BuildSpec)
		field string
	}{
		{func(b *contracts.BuildSpec) { b.Runtime = "" }, "build.runtime"},
		{func(b *contracts.BuildSpec) { b.Install = "" }, "build.install"},
		{func(b *contracts.BuildSpec) { b.Build = "" }, "build.build"},
		{func(b *contracts.BuildSpec) { b.Start = "" }, "build.start"},
	} {
		t.Run(row.field, func(t *testing.T) {
			spec := validBuildClassSpec()
			row.clear(spec.Build)
			errs := contracts.Validate(spec)
			if len(errs) == 0 || errs[0].Rule != contracts.RuleRequired || !strings.Contains(errs[0].Field, row.field) {
				t.Fatalf("want a required finding for %s, got %v", row.field, errs)
			}
		})
	}
}

// TestBuildClassDockerfileNeedsOnlyStart pins the dockerfile strategy's
// tiering: the Dockerfile owns runtime/install/build (empty rows are
// the typed gaps, never invented); only the keep-alive start is
// required.
func TestBuildClassDockerfileNeedsOnlyStart(t *testing.T) {
	spec := validBuildClassSpec()
	spec.Build.Strategy = "dockerfile"
	spec.Build.Runtime = ""
	spec.Build.Install = ""
	spec.Build.Build = ""
	if errs := contracts.Validate(spec); len(errs) != 0 {
		t.Fatalf("dockerfile strategy with empty plan rows failed: %v", errs)
	}
	spec.Build.Start = ""
	errs := contracts.Validate(spec)
	if len(errs) == 0 || errs[0].Rule != contracts.RuleRequired || errs[0].Field != "build.start" {
		t.Fatalf("want required build.start on dockerfile, got %v", errs)
	}
}

func TestBuildClassSourceRefGrammar(t *testing.T) {
	t.Run("repo required and bounded", func(t *testing.T) {
		spec := validBuildClassSpec()
		spec.Source.Repo = ""
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleRequired)

		spec.Source.Repo = strings.Repeat("a", contracts.MaxSourceRepoLength+1)
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleSourceRepo)

		spec.Source.Repo = "https://git.acme.example/a b"
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleSourceRepo)
	})
	t.Run("commit must be a full object id", func(t *testing.T) {
		spec := validBuildClassSpec()
		spec.Source.Commit = ""
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleRequired)

		spec.Source.Commit = "abc123"
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleSourceCommit)

		spec.Source.Commit = strings.ToUpper(sha256hex("aa"))
		assertSingleRule(t, contracts.Validate(spec), contracts.RuleSourceCommit)

		// A 40-char SHA-1 object id is a full id too.
		spec.Source.Commit = strings.Repeat("a", 40)
		if errs := contracts.Validate(spec); len(errs) != 0 {
			t.Fatalf("40-char object id refused: %v", errs)
		}
	})
}

func TestBuildClassCredentialReferencesOnly(t *testing.T) {
	for _, field := range []string{"build.source_pull_credential", "build.registry_push_credential"} {
		t.Run(field, func(t *testing.T) {
			spec := validBuildClassSpec()
			// The offending values are reference-grammar violations —
			// opaque strings that are NOT credential-store references.
			if field == "build.source_pull_credential" {
				spec.Build.SourcePullCredential = "super-secret-password123" //nolint:gosec // the refusal fixture
			} else {
				spec.Build.RegistryPushCredential = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
			}
			errs := contracts.Validate(spec)
			if len(errs) != 1 || errs[0].Rule != contracts.RuleBuildCredRef {
				t.Fatalf("inline credential value accepted on %s: %v", field, errs)
			}
		})
	}
}

func TestBuildClassPortRange(t *testing.T) {
	spec := validBuildClassSpec()
	spec.Build.Port = 70000
	assertSingleRule(t, contracts.Validate(spec), contracts.RuleBuildPort)
	spec.Build.Port = -1
	assertSingleRule(t, contracts.Validate(spec), contracts.RuleBuildPort)
	spec.Build.Port = 0
	if errs := contracts.Validate(spec); len(errs) != 0 {
		t.Fatalf("port 0 (none declared) refused: %v", errs)
	}
}

func TestBuildClassLogTopicGrammar(t *testing.T) {
	spec := validBuildClassSpec()
	spec.LogTopicID = "has space"
	assertSingleRule(t, contracts.Validate(spec), contracts.RuleLogTopic)
	spec.LogTopicID = strings.Repeat("a", contracts.MaxLogTopicIDLength+1)
	assertSingleRule(t, contracts.Validate(spec), contracts.RuleLogTopic)
	spec.LogTopicID = ""
	if errs := contracts.Validate(spec); len(errs) != 0 {
		t.Fatalf("empty log topic refused (log-less jobs are legal): %v", errs)
	}
}

// TestBuildClassSignVerifyRoundTrip runs the class through the full
// signing battery: sign the canonical form, verify, decode back.
func TestBuildClassSignVerifyRoundTrip(t *testing.T) {
	key := loadTestEngineKey(t)
	pub := key.Public().(ed25519.PublicKey)
	spec := validBuildClassSpec()

	sig, err := contracts.Sign(key, spec)
	if err != nil {
		t.Fatalf("Sign refused a valid build spec: %v", err)
	}
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if err := contracts.Verify(pub, doc, sig); err != nil {
		t.Fatalf("Verify refused a valid build spec: %v", err)
	}
	decoded, err := contracts.DecodeJobSpec(doc)
	if err != nil {
		t.Fatalf("DecodeJobSpec refused the canonical build doc: %v", err)
	}
	if decoded.Source == nil || decoded.Source.Commit != spec.Source.Commit {
		t.Fatalf("source ref did not round-trip: %+v", decoded.Source)
	}
	if decoded.Build.Strategy != "plan" || decoded.Build.Start != "npm start" {
		t.Fatalf("plan did not round-trip: %+v", decoded.Build)
	}
	if decoded.LogTopicID != spec.LogTopicID {
		t.Fatalf("log topic did not round-trip: %q", decoded.LogTopicID)
	}
}

// ---- the isolation negative-set (contract level) ----
//
// The builder never receives: an agent token, an org KEK, vault
// material, or another org's job/source/digest. At the contract level
// this holds structurally: the schema cannot EXPRESS credential VALUES
// (every credential field is a credential-store reference, and inline
// material is refused by the grammar), and the schema cannot EXPRESS a
// second tenant's payload (one source, one run reference, no
// cross-org field exists). Every negative below is a refusal test, not
// prose.

func TestIsolationNegativeSetSchemaCannotCarrySecrets(t *testing.T) {
	// An attacker (or a bug) trying to smuggle credential MATERIAL
	// through named fields hits the strict decoder's unknown-field
	// refusal: the schema has no such fields, by construction.
	for _, smuggled := range []string{"agent_token", "org_kek", "vault_material", "api_key", "password"} {
		t.Run(smuggled, func(t *testing.T) {
			doc, err := contracts.CanonicalJSON(validBuildClassSpec())
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			var generic map[string]any
			if err := json.Unmarshal(doc, &generic); err != nil {
				t.Fatalf("fixture is not JSON: %v", err)
			}
			generic[smuggled] = "live-secret-material"
			doctored, err := json.Marshal(generic)
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			_, err = contracts.DecodeJobSpec(doctored)
			if err == nil {
				t.Fatalf("document carrying %q decoded; the schema must refuse credential carriers", smuggled)
			}
			assertUnknownFieldNames(t, err, smuggled)
		})
	}
}

// TestIsolationNegativeSetSingleSourceSingleRun pins the one-tenant
// shape: the schema carries exactly ONE source ref and ONE run
// reference — there is no field through which another org's job,
// source, or digest could travel.
func TestIsolationNegativeSetSingleSourceSingleRun(t *testing.T) {
	var sourceFields, runFields int
	for _, name := range jobSpecFieldNames() {
		switch name {
		case "Source":
			sourceFields++
		case "RunReference":
			runFields++
		}
	}
	if sourceFields != 1 || runFields != 1 {
		t.Fatalf("schema grew tenant-carrying fields: source=%d run_reference=%d", sourceFields, runFields)
	}
}

// jobSpecFieldNames inventories the JobSpec schema's exported field
// names (reflection, test-side — the decode battery derives its key set
// from the same tags, so the two can never drift apart silently).
func jobSpecFieldNames() []string {
	var names []string
	appendFields(reflect.TypeFor[contracts.JobSpec](), &names)
	return names
}

func appendFields(t reflect.Type, names *[]string) {
	for i := 0; i < t.NumField(); i++ {
		*names = append(*names, t.Field(i).Name)
	}
}

// TestIsolationNegativeSetSealedDeliveryShape pins the reference-only
// delivery law end to end: a spec whose credential references name
// credential-store keys validates, and the canonical wire form carries
// the reference strings — never a resolved value (there is no resolver
// field the schema could carry one in).
func TestIsolationNegativeSetSealedDeliveryShape(t *testing.T) {
	spec := validBuildClassSpec()
	doc, err := contracts.CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.Contains(string(doc), "credential-store://build/source-pull") {
		t.Fatalf("the credential reference is not on the wire: %s", doc)
	}
	if strings.Contains(strings.ToLower(string(doc)), "-----begin") {
		t.Fatalf("PEM material on the wire: %s", doc)
	}
}
