package contracts_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// The machine-side middleman protocol's golden wire fixtures (R2.13's
// first compat fixtures — the battery's seed). Every op's request and
// reply, the handshake's accept and loud refusal, and each named
// refusal shape are pinned byte-for-byte under
// testdata/golden/middleman. A wire change that moves any pinned
// document fails here, forcing an explicit, reviewed fixture update —
// the test pin law's local form: a protocol change cannot land
// silently.
//
// The documents carry no signatures: the socket's authentication is the
// socket security law (peer credentials, root-owned path), not message
// signatures. The canonical form is pinned for determinism — two
// consumers holding the same document always produce the same bytes.
//
//	go test -run TestGoldenMiddlemanWireFixtures -update-golden
//
// regenerates the fixtures after a DELIBERATE wire change.

// goldenMiddlemanPath is where the protocol's fixtures live (a
// subdirectory of the signed job fixtures' flat namespace).
func goldenMiddlemanPath(name string) string {
	return filepath.Join("testdata", "golden", "middleman", name+".json")
}

// pinGoldenDoc pins one wire document: the pinned bytes must be exactly
// the canonical encoding of doc, and the pinned bytes must decode (via
// the strict decoder) back to a document whose canonical form is
// byte-identical.
func pinGoldenDoc[T any](t *testing.T, name string, doc T, decode func([]byte) (T, error)) {
	t.Helper()
	canonical, err := contracts.CanonicalMiddlemanJSON(doc)
	if err != nil {
		t.Fatalf("canonical encode: %v", err)
	}
	path := goldenMiddlemanPath(name)

	if *updateGolden {
		if err := os.WriteFile(path, canonical, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		return
	}

	pinned, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned fixture (run with -update-golden after a deliberate wire change): %v", err)
	}
	if !bytes.Equal(canonical, pinned) {
		t.Fatalf("canonical encoding drifted from the pinned fixture %s:\n pinned: %s\n current: %s", name, pinned, canonical)
	}
	decoded, err := decode(pinned)
	if err != nil {
		t.Fatalf("pinned fixture %s no longer decodes: %v", name, err)
	}
	recanonical, err := contracts.CanonicalMiddlemanJSON(decoded)
	if err != nil {
		t.Fatalf("canonical re-encode: %v", err)
	}
	if !bytes.Equal(recanonical, pinned) {
		t.Fatalf("decoded fixture %s re-encodes differently:\n pinned: %s\n decoded: %s", name, pinned, recanonical)
	}
}

// middlemanFixtureTime is the frozen compose time all fixture
// envelopes use (absolute epoch-millisecond deadlines pin
// deterministically).
var middlemanFixtureTime = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func middlemanFixtureEnvelope(op, opID string, span time.Duration) contracts.Envelope {
	return contracts.Envelope{
		Op:             op,
		OpID:           opID,
		DeadlineUnixMs: middlemanFixtureTime.Add(span).UnixMilli(),
	}
}

// TestGoldenMiddlemanWireFixtures pins every op's request and reply.
func TestGoldenMiddlemanWireFixtures(t *testing.T) {
	t.Run("prepare", func(t *testing.T) {
		req := contracts.PrepareRequest{
			Envelope: middlemanFixtureEnvelope(contracts.OpPrepare, "op-prepare-0001", time.Minute),
			Delivery: validFixtureDelivery(),
		}
		pinGoldenDoc(t, "prepare-request", req, contracts.DecodePrepareRequest)

		rep := contracts.PrepareReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpPrepare, OpID: "op-prepare-0001", OK: true},
			Handle: &contracts.RunnerHandle{
				HandleID:        "handle-0001",
				Forge:           contracts.ForgeGitHub,
				JobID:           "job-20261106-000007",
				RunReference:    "acme/payments@main:run-420",
				Attempt:         1,
				ServiceUnit:     "bmc-runner-run-420.service",
				StartedAtUnixMs: middlemanFixtureTime.Add(30 * time.Second).UnixMilli(),
			},
		}
		pinGoldenDoc(t, "prepare-reply", rep, contracts.DecodePrepareReply)
	})

	t.Run("prepare-refused-busy", func(t *testing.T) {
		busy := contracts.RefusalBusyOp(contracts.OpPrepare)
		rep := contracts.PrepareReply{
			Reply:  contracts.ReplyHeader{Op: contracts.OpPrepare, OpID: "op-prepare-0002", Refusal: &busy},
			Handle: nil,
		}
		pinGoldenDoc(t, "prepare-reply-busy", rep, contracts.DecodePrepareReply)
	})

	t.Run("machine-facts", func(t *testing.T) {
		req := contracts.MachineFactsRequest{Envelope: middlemanFixtureEnvelope(contracts.OpMachineFacts, "op-facts-0001", 10*time.Second)}
		pinGoldenDoc(t, "machine-facts-request", req, contracts.DecodeMachineFactsRequest)

		rep := contracts.MachineFactsReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpMachineFacts, OpID: "op-facts-0001", OK: true},
			Facts: &contracts.Facts{
				Hostname:      "packing-07",
				Arch:          "x86_64",
				OS:            "linux",
				OSVersion:     "Debian GNU/Linux 13 (trixie)",
				KernelVersion: "6.12.8-bmc",
				MachineID:     "b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
			},
		}
		pinGoldenDoc(t, "machine-facts-reply", rep, contracts.DecodeMachineFactsReply)
	})

	t.Run("clean-cycle", func(t *testing.T) {
		req := contracts.RunCleanCycleRequest{
			Envelope: middlemanFixtureEnvelope(contracts.OpRunCleanCycle, "op-clean-0001", time.Minute),
			Clean: contracts.CleanOp{Targets: []contracts.CleanTarget{
				{Kind: contracts.CleanTargetContainer, Ref: "bmc-runner-run-420"},
				{Kind: contracts.CleanTargetStage, Ref: "/var/lib/runnermand/stages/op-prepare-0001"},
			}},
		}
		pinGoldenDoc(t, "clean-cycle-request", req, contracts.DecodeRunCleanCycleRequest)

		rep := contracts.RunCleanCycleReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpRunCleanCycle, OpID: "op-clean-0001", OK: true},
			Receipt: &contracts.Receipt{
				CycleID:  "op-clean-0001",
				Scrubbed: req.Clean.Targets,
				AtUnixMs: middlemanFixtureTime.Add(45 * time.Second).UnixMilli(),
			},
		}
		pinGoldenDoc(t, "clean-cycle-reply", rep, contracts.DecodeRunCleanCycleReply)
	})

	t.Run("health", func(t *testing.T) {
		// Health's envelope is the short-deadline law's fixture: the
		// deadline sits inside MaxHealthDeadline.
		req := contracts.HealthRequest{Envelope: middlemanFixtureEnvelope(contracts.OpHealth, "op-health-0001", contracts.MaxHealthDeadline)}
		pinGoldenDoc(t, "health-request", req, contracts.DecodeHealthRequest)

		rep := contracts.HealthReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpHealth, OpID: "op-health-0001", OK: true},
			Health: &contracts.HealthReport{
				Healthy:       true,
				DaemonVersion: "runnermand-0.1.0",
				UptimeSeconds: 3600,
			},
		}
		pinGoldenDoc(t, "health-reply", rep, contracts.DecodeHealthReply)
	})

	t.Run("sample-metrics", func(t *testing.T) {
		window := contracts.MetricsWindow{
			FromUnixMs: middlemanFixtureTime.UnixMilli(),
			ToUnixMs:   middlemanFixtureTime.Add(time.Minute).UnixMilli(),
		}
		req := contracts.SampleMetricsRequest{Envelope: middlemanFixtureEnvelope(contracts.OpSampleMetrics, "op-metrics-0001", 30*time.Second), Window: window}
		pinGoldenDoc(t, "sample-metrics-request", req, contracts.DecodeSampleMetricsRequest)

		rep := contracts.SampleMetricsReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpSampleMetrics, OpID: "op-metrics-0001", OK: true},
			Metrics: &contracts.RunnerMetrics{
				Window: window,
				Samples: []contracts.MetricSample{
					{Runner: "handle-0001", Slice: "slice-01", CPUMillicores: 2400, MemoryBytes: 3 * GiB, DiskBytes: 12 * GiB, AtUnixMs: middlemanFixtureTime.Add(30 * time.Second).UnixMilli()},
				},
			},
		}
		pinGoldenDoc(t, "sample-metrics-reply", rep, contracts.DecodeSampleMetricsReply)
	})

	t.Run("tap-console", func(t *testing.T) {
		req := contracts.TapConsoleRequest{
			Envelope: middlemanFixtureEnvelope(contracts.OpTapConsole, "op-tap-0001", time.Minute),
			Job:      contracts.JobRef{JobID: "job-20261106-000009", RunReference: "acme/web@main:run-99", Attempt: 1, FromSequence: 42},
		}
		pinGoldenDoc(t, "tap-console-request", req, contracts.DecodeTapConsoleRequest)

		rep := contracts.TapConsoleReply{
			Reply: contracts.ReplyHeader{Op: contracts.OpTapConsole, OpID: "op-tap-0001", OK: true},
			Stream: &contracts.LogStream{
				StreamID: "tap-0001",
				JobID:    "job-20261106-000009",
				Sequence: 42,
				Masked:   true,
				Line:     "deploy step 2 of 5 finished",
			},
		}
		pinGoldenDoc(t, "tap-console-reply", rep, contracts.DecodeTapConsoleReply)
	})
}

// TestGoldenHandshakeFixtures pins the handshake's two outcomes: the
// exact-match accept and the loud refusal document naming BOTH
// versions.
func TestGoldenHandshakeFixtures(t *testing.T) {
	t.Run("hello-accept", func(t *testing.T) {
		req := contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion, AgentBuild: "agent-2241"}
		pinGoldenDoc(t, "hello-request", req, contracts.DecodeHelloRequest)

		rep := contracts.NegotiateHello(req, contracts.ProtocolVersion)
		pinGoldenDoc(t, "hello-accept", rep, contracts.DecodeHelloReply)
	})

	t.Run("hello-refuse", func(t *testing.T) {
		// The skew case as the update law meets it: a half-applied
		// update left the pair skewed — the agent announces v1, the
		// daemon already implements v2. Any unequal pair refuses;
		// the direction of the skew does not matter to the law.
		req := contracts.HelloRequest{ProtocolVersion: contracts.ProtocolVersion, AgentBuild: "agent-2242"}
		pinGoldenDoc(t, "hello-request-skew", req, contracts.DecodeHelloRequest)

		rep := contracts.NegotiateHello(req, contracts.ProtocolVersion+1)
		if rep.Accepted || rep.Refusal == nil {
			t.Fatalf("test is broken: the skew case must refuse, got %+v", rep)
		}
		pinGoldenDoc(t, "hello-refuse", rep, contracts.DecodeHelloReply)
	})
}

// TestGoldenRefusalFixtures pins each named refusal shape as its own
// wire document (the typed vocabulary, never a free-form error string).
func TestGoldenRefusalFixtures(t *testing.T) {
	shapes := map[string]contracts.Refusal{
		"refusal-busy":                 contracts.RefusalBusyOp(contracts.OpPrepare),
		"refusal-deadline-exceeded":    contracts.RefusalDeadline(),
		"refusal-unknown-job":          contracts.RefusalUnknownJobRef("job-20261106-000009"),
		"refusal-unknown-target":       contracts.RefusalUnknownTargetRef(contracts.CleanTargetStage, "/var/lib/runnermand/stages/op-prepare-0001"),
		"refusal-controller-displaced": contracts.RefusalDisplacedBy("agent-build-2242"),
		"refusal-unknown-op":           contracts.RefusalUnknownOpName("exec_shell"),
	}
	for name, refusal := range shapes {
		t.Run(name, func(t *testing.T) {
			if err := refusal.Validate(); err != nil {
				t.Fatalf("fixture refusal is not valid: %v", err)
			}
			pinGoldenDoc(t, name, refusal, decodeRefusal)
		})
	}
}

// decodeRefusal decodes a bare refusal document strictly.
func decodeRefusal(doc []byte) (contracts.Refusal, error) {
	return contracts.DecodeRefusal(doc)
}
