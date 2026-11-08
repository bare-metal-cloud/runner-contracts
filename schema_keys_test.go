package contracts_test

import (
	"reflect"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// jsonKeysOf derives a struct's exact json-tag key set, in declaration
// order (the battery's mirror of the module's own schemaFieldNames,
// which is unexported).
func jsonKeysOf(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%T is not a struct", v)
	}
	var keys []string
	for i := 0; i < typ.NumField(); i++ {
		tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		keys = append(keys, tag)
	}
	return keys
}

// wireSchemaKeySets is the wire schema's key inventory: every type the
// module carries on the wire or serializes as a finding — the 32
// middleman socket-protocol types, then the job-spec/cancel family
// (JobSpec's own and nested types, CancelSpec, Reason) and the
// typed-validation finding — each with the exact json-tag key set its
// struct may carry. The battery pins the inventory so ANY schema change
// — including adding an omitempty field, which moves no golden fixture
// (an empty optional key never serializes) but still breaks older peers
// (their strict decoder refuses the new key as unknown_field) — fails
// here and must be a deliberate, reviewed wire change with its version
// decision made explicit.
var wireSchemaKeySets = []struct {
	typ  any
	keys []string
}{
	// The middleman socket protocol's document and payload types.
	{contracts.Envelope{}, []string{"op", "op_id", "deadline_unix_ms"}},
	{contracts.ReplyHeader{}, []string{"op", "op_id", "ok", "refusal"}},
	{contracts.PrepareRequest{}, []string{"envelope", "delivery"}},
	{contracts.PrepareReply{}, []string{"reply", "handle"}},
	{contracts.MachineFactsRequest{}, []string{"envelope"}},
	{contracts.MachineFactsReply{}, []string{"reply", "facts"}},
	{contracts.RunCleanCycleRequest{}, []string{"envelope", "clean"}},
	{contracts.RunCleanCycleReply{}, []string{"reply", "receipt"}},
	{contracts.HealthRequest{}, []string{"envelope"}},
	{contracts.HealthReply{}, []string{"reply", "health"}},
	{contracts.SampleMetricsRequest{}, []string{"envelope", "window"}},
	{contracts.SampleMetricsReply{}, []string{"reply", "metrics"}},
	{contracts.TapConsoleRequest{}, []string{"envelope", "job"}},
	{contracts.TapConsoleReply{}, []string{"reply", "stream"}},
	{contracts.HelloRequest{}, []string{"protocol_version", "agent_build"}},
	{contracts.HelloReply{}, []string{"accepted", "protocol_version", "refusal"}},
	{contracts.HandshakeRefusal{}, []string{"agent_protocol_version", "daemon_protocol_version", "expected", "message"}},
	{contracts.Refusal{}, []string{"name", "message", "detail"}},
	{contracts.Delivery{}, []string{"delivery_attempt", "job_id", "run_reference", "attempt", "forge", "start_render", "fresh_registration_token", "digest_pin", "artifacts"}},
	{contracts.DeliveryArtifact{}, []string{"name", "reference", "digest"}},
	{contracts.RunnerHandle{}, []string{"handle_id", "forge", "job_id", "run_reference", "attempt", "service_unit", "started_at_unix_ms"}},
	{contracts.Facts{}, []string{"hostname", "arch", "os", "os_version", "kernel_version", "machine_id", "drift"}},
	{contracts.CleanOp{}, []string{"targets"}},
	{contracts.CleanTarget{}, []string{"kind", "ref"}},
	{contracts.Receipt{}, []string{"cycle_id", "scrubbed", "at_unix_ms"}},
	{contracts.HealthReport{}, []string{"healthy", "daemon_version", "uptime_seconds", "in_flight_op", "drift"}},
	{contracts.Drift{}, []string{"kind", "detail"}},
	{contracts.MetricsWindow{}, []string{"from_unix_ms", "to_unix_ms"}},
	{contracts.RunnerMetrics{}, []string{"window", "samples"}},
	{contracts.MetricSample{}, []string{"runner", "slice", "cpu_millicores", "memory_bytes", "disk_bytes", "at_unix_ms"}},
	{contracts.JobRef{}, []string{"job_id", "run_reference", "attempt", "from_sequence"}},
	{contracts.LogStream{}, []string{"stream_id", "job_id", "sequence", "masked", "line", "eof"}},

	// The job-spec/cancel family: the signed job document and every
	// type nested inside it, the cancel directive, the shared reason
	// vocabulary, and the typed validation finding.
	{contracts.JobSpec{}, []string{"job_id", "run_reference", "attempt", "source", "image", "command", "services", "build", "env", "artifact_inputs", "artifact_outputs", "timeout_seconds", "limits", "egress_allowlist", "label_requirements", "metering_tags", "log_topic_id"}},
	{contracts.SourceRef{}, []string{"repo", "commit"}},
	{contracts.ServiceContainer{}, []string{"name", "image", "command"}},
	{contracts.BuildSpec{}, []string{"base_image", "strategy", "runtime", "install", "build", "start", "port", "source_pull_credential", "registry_push_credential"}},
	{contracts.EnvEntry{}, []string{"name", "value", "secret_reference"}},
	{contracts.ArtifactInput{}, []string{"name", "reference"}},
	{contracts.ArtifactOutput{}, []string{"name", "repository", "tags"}},
	{contracts.ResourceLimits{}, []string{"cpu_millicores", "memory_bytes", "disk_bytes"}},
	{contracts.IdempotencyKey{}, []string{"run_reference", "attempt"}},
	{contracts.CancelSpec{}, []string{"job_id", "run_reference", "attempt", "reason"}},
	{contracts.Reason{}, []string{"class", "message"}},
	{contracts.ValidationError{}, []string{"field", "rule", "message"}},
}

// wireSchemaKeySetCount is the inventory's pinned length (the refusal
// vocabulary's count pin's shape): a new wire type — middleman or
// job-spec family — cannot ship without adding its row here AND bumping
// this count, so the growth is always a deliberate, reviewed change.
const wireSchemaKeySetCount = 44

// TestWireSchemaKeySetsPinned pins the wire schema's key inventory (see
// wireSchemaKeySets for why the golden fixtures alone cannot do this).
func TestWireSchemaKeySetsPinned(t *testing.T) {
	if len(wireSchemaKeySets) != wireSchemaKeySetCount {
		t.Fatalf("the key inventory grew to %d types; the count pin is %d — add a row for the new type's exact key set and bump the count deliberately (a schema change is a deliberate wire change: make the version decision explicit)", len(wireSchemaKeySets), wireSchemaKeySetCount)
	}
	for _, row := range wireSchemaKeySets {
		name := reflect.TypeOf(row.typ).Name()
		t.Run(name, func(t *testing.T) {
			got := jsonKeysOf(t, row.typ)
			if !reflect.DeepEqual(got, row.keys) {
				t.Fatalf("the wire schema gained or lost keys on %s:\n pinned: %v\n current: %v — a schema change is a deliberate wire change: make the version decision explicit and update this pin with it", name, row.keys, got)
			}
		})
	}
}

// TestWireSchemaKeySetPinCatchesAdditiveField is the pin's own
// demonstration case — the exact hole this battery had: an additive
// omitempty field on a nested job-spec type moves no golden fixture
// byte (an empty optional key never serializes), so only THIS pin can
// catch it. The test replays the reviewer's probe (a swap_bytes knob on
// ResourceLimits) through the pin's own comparison and asserts the
// comparison refuses it, so the pin's protection is demonstrated rather
// than assumed.
func TestWireSchemaKeySetPinCatchesAdditiveField(t *testing.T) {
	// mutatedResourceLimits is the would-be schema change: today's
	// ResourceLimits plus one additive omitempty field.
	type mutatedResourceLimits struct {
		CPUMillicores int64 `json:"cpu_millicores"`
		MemoryBytes   int64 `json:"memory_bytes"`
		DiskBytes     int64 `json:"disk_bytes"`
		SwapBytes     int64 `json:"swap_bytes,omitempty"`
	}

	var pinned []string
	for _, row := range wireSchemaKeySets {
		if reflect.TypeOf(row.typ).Name() == "ResourceLimits" {
			pinned = row.keys
			break
		}
	}
	if pinned == nil {
		t.Fatalf("no ResourceLimits row in the key inventory; the count pin or the family drifted")
	}
	got := jsonKeysOf(t, mutatedResourceLimits{})
	if reflect.DeepEqual(got, pinned) {
		t.Fatalf("an additive omitempty field produced the pinned key set; the pin would NOT catch the change: %v", got)
	}
}
