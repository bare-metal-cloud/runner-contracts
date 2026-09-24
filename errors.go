package contracts

import (
	"fmt"
	"strings"
)

// ValidationError is one typed, machine-readable validation finding.
// Rule is a stable machine-readable rule identifier (see the Rule*
// constants), Field is the JSON path of the offending field, and
// Message is the human-readable explanation.
type ValidationError struct {
	Field   string `json:"field"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed (rule=%s field=%s): %s", e.Rule, e.Field, e.Message)
}

// ValidationErrors is the typed error list the validation battery
// returns. An empty list means the document is valid.
type ValidationErrors []ValidationError

// Error implements the error interface by joining the findings.
func (errs ValidationErrors) Error() string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "; ")
}

// The Rule* constants are the machine-readable rule identifiers carried
// by ValidationError. Consumers match on these, never on message text.
const (
	RuleUnknownField     = "unknown_field"
	RuleMalformed        = "malformed_document"
	RuleRequired         = "required"
	RuleJobID            = "job_id"
	RuleRunReference     = "run_reference"
	RuleAttempt          = "attempt"
	RuleDigestOnly       = "digest_only"
	RuleOCIRepository    = "oci_repository"
	RuleOutputTag        = "output_tag"
	RuleServiceName      = "service_name"
	RuleServiceDuplicate = "service_duplicate"
	RuleServiceCount     = "service_count"
	RuleEnvName          = "env_name"
	RuleEnvConflict      = "env_conflict"
	RuleEnvRequired      = "env_required"
	RuleEnvDuplicate     = "env_duplicate"
	RuleEnvCount         = "env_count"
	RuleSecretReference  = "secret_reference"
	RuleCommand          = "command"
	RuleTimeout          = "timeout"
	RuleLimitsPositive   = "limits_positive"
	RuleLimitsBounded    = "limits_bounded"
	RuleEgressSuffix     = "egress_suffix"
	RuleTagKey           = "metering_tag_key"
	RuleTagValue         = "metering_tag_value"
	RuleTagCount         = "metering_tag_count"
	RuleArtifactName     = "artifact_name"
	RuleArtifactCount    = "artifact_count"
	RuleNotCanonical     = "not_canonical"
	RuleSignatureInvalid = "signature_invalid"
	RuleReasonClass      = "reason_class"
	RuleReasonMessage    = "reason_message"
)

// The schema's sanity bounds. They are admission sanity limits, not
// product limits: the platform's watchdog and the Pool Manager enforce
// their own maxima on top of them.
const (
	MaxTimeoutSeconds  = 86400 // one day
	MinTimeoutSeconds  = 1
	MinCPUMillicores   = 100
	MaxCPUMillicores   = 614400 // 614 cores
	MinMemoryBytes     = 64 * 1024 * 1024
	MaxMemoryBytes     = 4 * 1024 * 1024 * 1024 * 1024
	MinDiskBytes       = 1024 * 1024 * 1024
	MaxDiskBytes       = 16 * 1024 * 1024 * 1024 * 1024
	MaxServices        = 8
	MaxEnvEntries      = 128
	MaxArtifactInputs  = 32
	MaxArtifactOutputs = 16
	MaxMeteringTags    = 32
	// MaxMeteringTagKeyLength bounds each metering tag key.
	MaxMeteringTagKeyLength = 64
	// MaxMeteringTagValueLength bounds each metering tag value.
	MaxMeteringTagValueLength = 256
	// MaxJobIDLength bounds the job identifier.
	MaxJobIDLength = 128
	// MaxRunReferenceLength bounds the run reference.
	MaxRunReferenceLength = 256
)
