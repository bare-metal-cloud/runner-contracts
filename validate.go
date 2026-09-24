package contracts

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// The grammars the validation battery enforces. They are deliberately
// conservative: a wire identifier only ever gets stricter, never looser.
var (
	// ociRepositoryRe matches a bare OCI repository path: lowercase
	// path components of alphanumerics and the optional separators
	// (dot, underscore, hyphen), joined by slashes. It deliberately
	// refuses a tag or a digest — those make a reference mutable or
	// are validated separately.
	ociRepositoryRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$`)

	// hostnameSuffixRe matches a lowercase hostname with at least two
	// labels (the egress allowlist speaks hostname suffixes; a bare
	// single label like "localhost" is never a useful egress target).
	hostnameSuffixRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

	// jobIDRe matches the platform-generated job identifier.
	jobIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

	// nameRe matches service container names and artifact names.
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

	// envNameRe matches environment variable names.
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// tagKeyRe matches a metering tag key.
	tagKeyRe = regexp.MustCompile(`^[a-z0-9_-]+$`)

	// outputTagRe matches an OCI distribution tag (applied at push
	// time on artifact outputs, never used to pull).
	outputTagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

	// secretSegmentRe matches one path segment of a credential-store
	// key: lowercase alphanumerics with the dot, underscore, and
	// hyphen separators.
	secretSegmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// Validate runs the schema's full validation battery over the spec and
// returns every finding. An empty return means the spec is valid.
//
// The battery is the law of record for the wire schema. Every rule here
// is pinned by a unit test inside the module (the red-first battery), so
// a law cannot silently change: the test fails first.
func Validate(spec JobSpec) ValidationErrors {
	var errs ValidationErrors
	add := func(e ValidationError) { errs = append(errs, e) }

	// Identity: job id, run reference, attempt.
	if spec.JobID == "" {
		add(required("job_id"))
	} else if len(spec.JobID) > MaxJobIDLength || !jobIDRe.MatchString(spec.JobID) {
		add(ValidationError{
			Field: "job_id",
			Rule:  RuleJobID,
			Message: fmt.Sprintf("job_id %q must be at most %d characters of letters, digits, dots, hyphens, and underscores, and must start with a letter or digit",
				spec.JobID, MaxJobIDLength),
		})
	}
	if spec.RunReference == "" {
		add(required("run_reference"))
	} else if len(spec.RunReference) > MaxRunReferenceLength || containsWhitespace(spec.RunReference) {
		add(ValidationError{
			Field: "run_reference",
			Rule:  RuleRunReference,
			Message: fmt.Sprintf("run_reference %q must be at most %d characters and carry no whitespace",
				spec.RunReference, MaxRunReferenceLength),
		})
	}
	if spec.Attempt < 1 {
		add(ValidationError{
			Field:   "attempt",
			Rule:    RuleAttempt,
			Message: fmt.Sprintf("attempt %d must be at least 1 (attempts are a 1-based counter)", spec.Attempt),
		})
	}

	// The digest-only law for every image-bearing field.
	if spec.Image == "" {
		add(required("image"))
	} else if e, bad := digestReferenceError("image", spec.Image); bad {
		add(e)
	}
	if spec.Build != nil {
		if spec.Build.BaseImage == "" {
			add(required("build.base_image"))
		} else if e, bad := digestReferenceError("build.base_image", spec.Build.BaseImage); bad {
			add(e)
		}
	}

	// The job's own command: required, every entry non-empty.
	if len(spec.Command) == 0 {
		add(required("command"))
	}
	for i, c := range spec.Command {
		if c == "" {
			add(commandError(fmt.Sprintf("command[%d]", i)))
		}
	}

	// Service containers.
	if len(spec.Services) > MaxServices {
		add(countError("services", len(spec.Services), MaxServices, RuleServiceCount, "service containers"))
	}
	seenServices := make(map[string]bool, len(spec.Services))
	for i, svc := range spec.Services {
		nameField := fmt.Sprintf("services[%d].name", i)
		switch {
		case svc.Name == "" || !nameRe.MatchString(svc.Name):
			add(ValidationError{
				Field: nameField,
				Rule:  RuleServiceName,
				Message: fmt.Sprintf("service name %q must be at most 63 lowercase letters, digits, and inner hyphens",
					svc.Name),
			})
		case seenServices[svc.Name]:
			add(ValidationError{
				Field:   nameField,
				Rule:    RuleServiceDuplicate,
				Message: fmt.Sprintf("service name %q is already used by an earlier container in this job", svc.Name),
			})
		}
		seenServices[svc.Name] = true
		if svc.Image == "" {
			add(required(fmt.Sprintf("services[%d].image", i)))
		} else if e, bad := digestReferenceError(fmt.Sprintf("services[%d].image", i), svc.Image); bad {
			add(e)
		}
		for j, c := range svc.Command {
			if c == "" {
				add(commandError(fmt.Sprintf("services[%d].command[%d]", i, j)))
			}
		}
	}

	// Environment entries.
	if len(spec.Env) > MaxEnvEntries {
		add(countError("env", len(spec.Env), MaxEnvEntries, RuleEnvCount, "env entries"))
	}
	seenEnv := make(map[string]bool, len(spec.Env))
	for i, entry := range spec.Env {
		nameField := fmt.Sprintf("env[%d].name", i)
		switch {
		case entry.Name == "" || !envNameRe.MatchString(entry.Name):
			add(ValidationError{
				Field:   nameField,
				Rule:    RuleEnvName,
				Message: fmt.Sprintf("env name %q must start with a letter or underscore and carry only letters, digits, and underscores", entry.Name),
			})
		case seenEnv[entry.Name]:
			add(ValidationError{
				Field:   nameField,
				Rule:    RuleEnvDuplicate,
				Message: fmt.Sprintf("env name %q is already set by an earlier entry in this job", entry.Name),
			})
		}
		seenEnv[entry.Name] = true
		switch {
		case entry.Value != nil && entry.SecretReference != nil:
			add(ValidationError{
				Field:   fmt.Sprintf("env[%d]", i),
				Rule:    RuleEnvConflict,
				Message: fmt.Sprintf("env entry %q carries both a plain value and a secret reference; an entry is exactly one of the two", entry.Name),
			})
		case entry.Value == nil && entry.SecretReference == nil:
			add(ValidationError{
				Field:   fmt.Sprintf("env[%d]", i),
				Rule:    RuleEnvRequired,
				Message: fmt.Sprintf("env entry %q carries neither a plain value nor a secret reference", entry.Name),
			})
		}
		if entry.SecretReference != nil && !isSecretReference(*entry.SecretReference) {
			add(ValidationError{
				Field: fmt.Sprintf("env[%d].secret_reference", i),
				Rule:  RuleSecretReference,
				Message: fmt.Sprintf("secret reference %q must name a platform credential-store key of the form credential-store://<namespace>/<key>, with at least two lowercase path segments and no secret material inline",
					*entry.SecretReference),
			})
		}
	}

	// Artifact inputs: digest-pinned references the job consumes.
	if len(spec.ArtifactInputs) > MaxArtifactInputs {
		add(countError("artifact_inputs", len(spec.ArtifactInputs), MaxArtifactInputs, RuleArtifactCount, "artifact inputs"))
	}
	for i, input := range spec.ArtifactInputs {
		if input.Name == "" || !nameRe.MatchString(input.Name) {
			add(ValidationError{
				Field:   fmt.Sprintf("artifact_inputs[%d].name", i),
				Rule:    RuleArtifactName,
				Message: fmt.Sprintf("artifact input name %q must be at most 63 lowercase letters, digits, and inner hyphens", input.Name),
			})
		}
		if input.Reference == "" {
			add(required(fmt.Sprintf("artifact_inputs[%d].reference", i)))
		} else if e, bad := digestReferenceError(fmt.Sprintf("artifact_inputs[%d].reference", i), input.Reference); bad {
			add(e)
		}
	}

	// Artifact outputs: bare repositories (tags are applied at push
	// time and are exempt from the digest-only law).
	if len(spec.ArtifactOutputs) > MaxArtifactOutputs {
		add(countError("artifact_outputs", len(spec.ArtifactOutputs), MaxArtifactOutputs, RuleArtifactCount, "artifact outputs"))
	}
	for i, output := range spec.ArtifactOutputs {
		if output.Name == "" || !nameRe.MatchString(output.Name) {
			add(ValidationError{
				Field:   fmt.Sprintf("artifact_outputs[%d].name", i),
				Rule:    RuleArtifactName,
				Message: fmt.Sprintf("artifact output name %q must be at most 63 lowercase letters, digits, and inner hyphens", output.Name),
			})
		}
		if output.Repository == "" {
			add(required(fmt.Sprintf("artifact_outputs[%d].repository", i)))
		} else if !ociRepositoryRe.MatchString(output.Repository) {
			add(ValidationError{
				Field:   fmt.Sprintf("artifact_outputs[%d].repository", i),
				Rule:    RuleOCIRepository,
				Message: fmt.Sprintf("artifact output repository %q must be a bare repository path (no tag, no digest); push-time tags are carried by the tags field", output.Repository),
			})
		}
		for j, tag := range output.Tags {
			if !outputTagRe.MatchString(tag) {
				add(ValidationError{
					Field:   fmt.Sprintf("artifact_outputs[%d].tags[%d]", i, j),
					Rule:    RuleOutputTag,
					Message: fmt.Sprintf("output tag %q must be at most 128 characters and start with a letter, digit, or underscore", tag),
				})
			}
		}
	}

	// Timeout, limits, egress, metering.
	if spec.TimeoutSeconds < MinTimeoutSeconds || spec.TimeoutSeconds > MaxTimeoutSeconds {
		add(ValidationError{
			Field:   "timeout_seconds",
			Rule:    RuleTimeout,
			Message: fmt.Sprintf("timeout_seconds %d must be between %d and %d", spec.TimeoutSeconds, MinTimeoutSeconds, MaxTimeoutSeconds),
		})
	}
	for _, lc := range []struct {
		field    string
		value    int64
		min, max int64
	}{
		{"limits.cpu_millicores", spec.Limits.CPUMillicores, MinCPUMillicores, MaxCPUMillicores},
		{"limits.memory_bytes", spec.Limits.MemoryBytes, MinMemoryBytes, MaxMemoryBytes},
		{"limits.disk_bytes", spec.Limits.DiskBytes, MinDiskBytes, MaxDiskBytes},
	} {
		if lc.value <= 0 {
			add(ValidationError{
				Field:   lc.field,
				Rule:    RuleLimitsPositive,
				Message: fmt.Sprintf("%s must be positive (got %d)", lc.field, lc.value),
			})
			continue
		}
		if lc.value < lc.min || lc.value > lc.max {
			add(ValidationError{
				Field:   lc.field,
				Rule:    RuleLimitsBounded,
				Message: fmt.Sprintf("%s %d is outside the sane admission range [%d, %d]", lc.field, lc.value, lc.min, lc.max),
			})
		}
	}
	for i, entry := range spec.EgressAllowlist {
		if !isHostnameSuffix(entry) {
			add(ValidationError{
				Field:   fmt.Sprintf("egress_allowlist[%d]", i),
				Rule:    RuleEgressSuffix,
				Message: fmt.Sprintf("egress allowlist entry %q must be a lowercase hostname suffix of at least two labels (no scheme, path, or wildcard); an empty allowlist is legal and means deny-all", entry),
			})
		}
	}
	if len(spec.MeteringTags) > MaxMeteringTags {
		add(countError("metering_tags", len(spec.MeteringTags), MaxMeteringTags, RuleTagCount, "metering tags"))
	}
	for key, value := range spec.MeteringTags {
		field := fmt.Sprintf("metering_tags[%s]", key)
		if key == "" || len(key) > MaxMeteringTagKeyLength || !tagKeyRe.MatchString(key) {
			add(ValidationError{
				Field: field,
				Rule:  RuleTagKey,
				Message: fmt.Sprintf("metering tag key %q must be at most %d lowercase letters, digits, underscores, and hyphens",
					key, MaxMeteringTagKeyLength),
			})
		}
		if len(value) > MaxMeteringTagValueLength {
			add(ValidationError{
				Field: field,
				Rule:  RuleTagValue,
				Message: fmt.Sprintf("metering tag value is %d characters, at most %d are allowed",
					len(value), MaxMeteringTagValueLength),
			})
		}
	}

	return errs
}

// digestReferenceError enforces the digest-only law for one image-bearing
// field: the reference must be a bare repository path anchored at a
// sha256 digest of 64 lowercase hex characters. When the reference
// violates the law it returns a ValidationError whose message names the
// offending reference; ok is true only when the reference is invalid.
func digestReferenceError(field, ref string) (ValidationError, bool) {
	invalid := func(reason string) (ValidationError, bool) {
		return ValidationError{
			Field: field,
			Rule:  RuleDigestOnly,
			Message: fmt.Sprintf("reference %q is not digest-pinned (%s); images are pulled only in the form <repository>@sha256:<64 lowercase hex>",
				ref, reason),
		}, true
	}
	repo, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return invalid("no digest anchor")
	}
	if !ociRepositoryRe.MatchString(repo) {
		return invalid("the repository part must be a bare repository path with no tag")
	}
	algo, body, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" {
		return invalid("the digest algorithm must be sha256")
	}
	if !isLowerHex64(body) {
		return invalid("the digest body must be 64 lowercase hex characters")
	}
	return ValidationError{}, false
}

// isSecretReference reports whether ref names a platform credential-store
// key: the credential-store:// scheme (exact, lowercase), followed by at
// least two path segments (namespace and key) of lowercase alphanumerics
// with dot, underscore, and hyphen separators. A single segment after the
// scheme is refused: a reference carries a key PATH, never secret
// material inline.
func isSecretReference(ref string) bool {
	const scheme = "credential-store://"
	rest, ok := strings.CutPrefix(ref, scheme)
	if !ok || rest == "" {
		return false
	}
	segments := strings.Split(rest, "/")
	if len(segments) < 2 {
		return false
	}
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		if !secretSegmentRe.MatchString(seg) {
			return false
		}
	}
	return true
}

// isHostnameSuffix reports whether entry is a valid egress allowlist
// entry: a lowercase hostname of at least two labels whose total length
// and label lengths are DNS-sane.
func isHostnameSuffix(entry string) bool {
	if len(entry) > 253 {
		return false
	}
	if !hostnameSuffixRe.MatchString(entry) {
		return false
	}
	for _, label := range strings.Split(entry, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func containsWhitespace(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) >= 0
}

func required(field string) ValidationError {
	return ValidationError{
		Field:   field,
		Rule:    RuleRequired,
		Message: fmt.Sprintf("%s is required", field),
	}
}

func commandError(field string) ValidationError {
	return ValidationError{
		Field:   field,
		Rule:    RuleCommand,
		Message: "command entries must be non-empty (argv entries are never blank)",
	}
}

func countError(field string, got, max int, rule string, what string) ValidationError {
	return ValidationError{
		Field:   field,
		Rule:    rule,
		Message: fmt.Sprintf("%s carries %d %s, at most %d are allowed", field, got, what, max),
	}
}
