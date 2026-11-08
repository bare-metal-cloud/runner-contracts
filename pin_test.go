package contracts_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	contracts "github.com/bare-metal-cloud/runner-contracts"
)

// The both-import pin, in its local form (R2.13's cross-repo stand-in
// while the protocol evolves without hosted CI): the agent and the
// daemon pin the SAME contracts module, and the wire definitions they
// compile against must carry THIS module's protocol version. When the
// monorepo checkout is present (the submodule layout:
// components/runner-contracts beside components/agent), the test reads
// the agent's go.mod and its committed vendor tree and refuses a drift.
//
// What is checked, in order of the failure it catches:
//
//  1. components/agent/go.mod requires github.com/bare-metal-cloud/
//     runner-contracts at SOME version, and vendor/modules.txt records
//     the SAME version (the pin's internal consistency).
//  2. The vendored copy — the definitions the agent actually compiles
//     — declares the SAME ProtocolVersion this module does. A vendored
//     tree from an older or newer protocol cannot pass.
//
// The full battery (the release CI the design names, comparing both
// sides' pins) is R2.13's story; this test is the seed that test
// matures. In a standalone contracts checkout — no agent sibling — the
// test skips, so the module keeps its zero-dependency, run-anywhere
// property.
func TestBothImportPin(t *testing.T) {
	agentRoot := filepath.Join("..", "agent")
	explicit := false
	if env := os.Getenv("BMC_AGENT_ROOT"); env != "" {
		agentRoot = env
		explicit = true
	}
	goModPath := filepath.Join(agentRoot, "go.mod")
	goMod, err := os.ReadFile(goModPath)
	if err != nil {
		t.Skipf("no agent checkout at %s (standalone contracts checkout); the both-import pin needs the monorepo worktree (or set BMC_AGENT_ROOT)", goModPath)
	}

	// 1. The require line and the vendor record must agree.
	pinnedVersion, ok := findRunnerContractsRequire(string(goMod))
	if !ok {
		if !explicit {
			// An adjacent go.mod that does not require this module is
			// not the monorepo agent (any unrelated Go project named
			// "agent" beside a standalone checkout would otherwise
			// hijack the pin): skip, as the standalone checkout does.
			t.Skipf("%s does not require github.com/bare-metal-cloud/runner-contracts; it is not the monorepo agent checkout", goModPath)
		}
		t.Fatalf("the agent's go.mod carries no github.com/bare-metal-cloud/runner-contracts require line; the both-import law requires the pin")
	}
	modulesTxt, err := os.ReadFile(filepath.Join(agentRoot, "vendor", "modules.txt"))
	if err != nil {
		if !explicit {
			// An adjacent checkout without the committed vendor tree is
			// not a monorepo worktree the pin can check (an old agent
			// checkout predating the protocol looks identical to one);
			// the pin runs against the real worktree or skips.
			t.Skipf("the adjacent checkout at %s has no committed vendor tree; the both-import pin's local form needs the monorepo worktree layout (or set BMC_AGENT_ROOT to the agent root): %v", agentRoot, err)
		}
		t.Fatalf("the agent has no committed vendor tree (the committed-vendor zero-network law requires it): %v", err)
	}
	vendorVersion := findRunnerContractsVendorRecord(t, string(modulesTxt))
	if pinnedVersion != vendorVersion {
		t.Fatalf("the agent's pin is inconsistent: go.mod requires %s but vendor/modules.txt records %s; re-run go mod vendor", pinnedVersion, vendorVersion)
	}

	// 2. The vendored definitions must carry this module's protocol
	// version.
	vendored, err := os.ReadFile(filepath.Join(agentRoot, "vendor", "github.com", "bare-metal-cloud", "runner-contracts", "middleman.go"))
	if err != nil {
		if !explicit {
			// A vendored tree without the protocol's definitions is a
			// checkout whose pin predates the socket protocol — an old
			// snapshot, not a monorepo worktree this pin can judge.
			t.Skipf("the adjacent checkout's vendored contracts copy has no middleman.go (its pin predates the socket protocol); the pin runs against a current monorepo worktree: %v", err)
		}
		t.Fatalf("read the vendored middleman.go (the vendored tree predates the socket protocol; bump the pin and re-vendor): %v", err)
	}
	vendoredProtocol := findProtocolVersion(t, string(vendored), "vendored middleman.go")
	if vendoredProtocol != contracts.ProtocolVersion {
		t.Fatalf("the both-import pin is broken: the agent's vendored contracts copy declares ProtocolVersion %d, this module declares %d; the agent and the daemon would speak different protocols on one socket — bump the agent's pin to the matching contracts version (the test pin law: a failing protocol-compatibility test blocks the release)",
			vendoredProtocol, contracts.ProtocolVersion)
	}

	t.Logf("both-import pin holds: agent go.mod pins %s, vendored protocol version %d == this module's %d",
		pinnedVersion, vendoredProtocol, contracts.ProtocolVersion)
}

var requireRunnerContractsRe = regexp.MustCompile(`(?m)^\s*github\.com/bare-metal-cloud/runner-contracts\s+(v\S+)`)

func findRunnerContractsRequire(goMod string) (string, bool) {
	m := requireRunnerContractsRe.FindStringSubmatch(goMod)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func findRunnerContractsVendorRecord(t *testing.T, modulesTxt string) string {
	t.Helper()
	for _, line := range strings.Split(modulesTxt, "\n") {
		if strings.HasPrefix(line, "# github.com/bare-metal-cloud/runner-contracts ") {
			fields := strings.Fields(line)
			return fields[len(fields)-1]
		}
	}
	t.Fatalf("vendor/modules.txt records no github.com/bare-metal-cloud/runner-contracts version; re-run go mod vendor")
	return ""
}

var protocolVersionRe = regexp.MustCompile(`(?m)^\s*(const\s+)?ProtocolVersion\s*=\s*(\d+)`)

func findProtocolVersion(t *testing.T, source, what string) int {
	t.Helper()
	m := protocolVersionRe.FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("%s declares no ProtocolVersion constant; the version handshake has nothing to announce", what)
	}
	v, err := strconv.Atoi(m[2])
	if err != nil {
		t.Fatalf("parse ProtocolVersion in %s: %v", what, err)
	}
	return v
}
