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

// wireSchemaKeySets is the middleman wire schema's key inventory: every
// wire document and payload type, with the exact json-tag key set its
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
}

// TestWireSchemaKeySetsPinned pins the wire schema's key inventory (see
// wireSchemaKeySets for why the golden fixtures alone cannot do this).
func TestWireSchemaKeySetsPinned(t *testing.T) {
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
