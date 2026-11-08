#!/usr/bin/env bash
# The release gate (R2.13, the test pin law): run EVERYTHING a new
# contracts version must pass BEFORE it is tagged. A red battery blocks
# the release — no tag goes out over a failing compatibility test.
#
# The steps:
#   1. gofmt-clean   — the formatted-source check CI enforces;
#   2. go vet        — the module's static analysis;
#   3. the battery   — go test ./... -count=1: the golden wire fixtures
#      (a wire change cannot land silently), the version-negotiation
#      matrix, the refusal vocabulary, the masked-versus-raw console
#      pair, and the local both-import pin (against a sibling agent
#      checkout when one is present);
#   4. the cross-repo both-import pin — the agent's and the daemon's
#      pins, compared against each other and against THIS module's
#      protocol version (scripts/check-both-import-pin.sh; set
#      BMC_AGENT_ROOT / BMC_DAEMON_ROOT to local checkouts, or let it
#      fetch the two public repos).
#
# Usage (from a clean contracts checkout, before tagging):
#   scripts/release-check.sh
#
# The release flow this gate sits in is documented in README.md
# ("Releasing a contracts version").

set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "RELEASE REFUSED: $1" >&2; exit 1; }

echo "== release-check: the test pin law's gate =="
echo
echo "[1/4] gofmt-clean"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	fail "gofmt-clean failed for:
${unformatted}"
fi
echo "      ok"

echo "[2/4] go vet"
go vet ./... || fail "go vet found problems"
echo "      ok"

echo "[3/4] the compat battery (go test ./... -count=1)"
go test ./... -count=1 || fail "the battery is red — fix or deliberately update the pins it protects before any release"
echo "      ok"

echo "[4/4] the cross-repo both-import pin"
scripts/check-both-import-pin.sh "$@" || fail "the agent's and the daemon's pins disagree with each other or with this module's protocol version"
echo
echo "release-check: green — the battery and both pins agree; tagging this version is permitted (the battery is the release gate, not a suggestion)"
