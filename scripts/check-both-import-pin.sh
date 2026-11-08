#!/usr/bin/env bash
# The both-import pin, in its cross-repo form (R2.13, the test pin law):
# the agent and the runnermand daemon BOTH import runner-contracts, and
# the protocol only works while both sides pin the SAME contracts
# version whose wire carries THIS module's protocol version. This check
# fails the release when the pins diverge:
#
#   1. the agent's go.mod pin equals the daemon's go.mod pin
#      (the both-import law: one protocol version, both sides);
#   2. each side's committed vendored copy declares the ProtocolVersion
#      THIS module declares (the definitions they compile against speak
#      this module's protocol).
#
# Sources, per side: a local checkout when --agent-root/--daemon-root
# (or BMC_AGENT_ROOT / BMC_DAEMON_ROOT) names one; otherwise the pin is
# FETCHED from GitHub at AGENT_REF / DAEMON_REF. Ref defaults are each
# repo's integration branch (the monorepo's dev-release, the daemon's
# main); override for a release audit of shipped refs.
#
# The fetch form's credential honesty (2026-11-08): only runner-contracts
# itself is public today — the monorepo (backend) and the daemon repo
# (runner-man) are PRIVATE, so the fetch needs a token that can read
# them. The script tries, in order: the gh CLI authenticated as the
# caller (works on a developer machine, and in hosted CI when the
# workflow's token can read the two repos), then the unauthenticated
# raw URL (works if the repos ever go public — the wire is public by
# design even though the repos are not). A hosted run that cannot read
# the private repos FAILS — the cross-repo pin check never silently
# passes because it could not look.
#
# Usage:
#   scripts/check-both-import-pin.sh [--agent-root DIR] [--daemon-root DIR]
#
# Exit 0: the pins agree. Exit 1: a divergence — a new contracts
# version must not be released while this fails (the test pin law: a
# failing protocol-compatibility test blocks a new version's release).

set -euo pipefail

ORG="bare-metal-cloud"
MODULE="runner-contracts"
AGENT_REPO="agent"        # the agent repo (a submodule of the backend monorepo)
AGENT_SUBDIR=""
AGENT_REF="${AGENT_REF:-main}" # the agent repo's integration branch
DAEMON_REPO="runner-man"  # the daemon repo; vendored at its root
DAEMON_REF="${DAEMON_REF:-main}"
RAW="https://raw.githubusercontent.com/${ORG}"

AGENT_ROOT="${BMC_AGENT_ROOT:-}"
DAEMON_ROOT="${BMC_DAEMON_ROOT:-}"

usage() { echo "usage: $0 [--agent-root DIR] [--daemon-root DIR]" >&2; exit 2; }
while [ $# -gt 0 ]; do
	case "$1" in
	--agent-root) AGENT_ROOT="$2"; shift 2 ;;
	--daemon-root) DAEMON_ROOT="$2"; shift 2 ;;
	-h|--help) usage ;;
	*) usage ;;
	esac
done

MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# read_side <label> <root-or-empty> <repo> <subdir> <ref>
#   Prints "pin vendor_version protocol_version" for one consumer side.
#   The pin comes from go.mod's require line; the protocol version from
#   the vendored copy of middleman.go (the definitions the side actually
#   compiles).
read_side() {
	label="$1"; root="$2"; repo="$3"; subdir="$4"; ref="$5"
	fetch() { # fetch <path-under-checkout> — local read or GitHub raw
		if [ -n "$root" ]; then
			cat "${root}/$1"
		else
			fetch_raw "${repo}" "${ref}" "${subdir}/$1"
		fi
	}
	if [ -z "$root" ]; then
		go_mod="$(fetch_raw "${repo}" "${ref}" "${subdir}/go.mod")"
	else
		if [ ! -f "${root}/go.mod" ]; then
			echo "FAIL ${label}: no go.mod at ${root} (set BMC_$(echo "$label" | tr 'a-z' 'A-Z')_ROOT to the checkout root, or drop the flag to fetch from GitHub)" >&2
			exit 1
		fi
		go_mod="$(cat "${root}/go.mod")"
	fi

	# The require line comes in both go.mod forms: a line inside a
	# require block (the module path first) and a single-line
	# "require <module> <version>" (the daemon's form).
	pin="$(printf '%s\n' "$go_mod" | sed -n -e 's/^[[:space:]]*github\.com\/bare-metal-cloud\/'"${MODULE}"'[[:space:]][[:space:]]*\(v[^[:space:]]*\).*/\1/p' -e 's/^require[[:space:]][[:space:]]*github\.com\/bare-metal-cloud\/'"${MODULE}"'[[:space:]][[:space:]]*\(v[^[:space:]]*\).*/\1/p' | head -n 1)"
	if [ -z "$pin" ]; then
		echo "FAIL ${label}: go.mod carries no ${MODULE} require line; the both-import law requires the pin" >&2
		exit 1
	fi

	vendored="$(fetch "vendor/github.com/${ORG}/${MODULE}/middleman.go" || true)"
	if [ -z "$vendored" ]; then
		echo "FAIL ${label}: the vendored copy has no middleman.go (its pin predates the socket protocol; bump the pin and re-vendor)" >&2
		exit 1
	fi
	proto="$(printf '%s\n' "$vendored" | sed -n 's/^[[:space:]]*const[[:space:]][[:space:]]*ProtocolVersion[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1)"
	if [ -z "$proto" ]; then
		echo "FAIL ${label}: the vendored middleman.go declares no ProtocolVersion constant" >&2
		exit 1
	fi
	echo "${pin} ${proto}"
}

# fetch_raw <repo> <ref> <path> — the file's bytes from GitHub, through
# the gh CLI when one is authenticated (the two consumer repos are
# private today), else the unauthenticated raw URL. The gh probe is
# strictly non-interactive (a token must already exist); a missing or
# unreadable source FAILS the check — it never silently passes.
fetch_raw() {
	repo="$1"; ref="$2"; path="$3"
	if command -v gh >/dev/null 2>&1 && [ -n "$(gh auth token 2>/dev/null)" ]; then
		if gh api -H "Accept: application/vnd.github.raw" "repos/${ORG}/${repo}/contents/${path}?ref=${ref}" </dev/null 2>/dev/null; then
			return 0
		fi
	fi
	if command -v curl >/dev/null 2>&1; then
		if curl -fsSL "${RAW}/${repo}/${ref}/${path}" </dev/null; then
			return 0
		fi
	fi
	echo "FAIL: cannot read ${repo}:${ref}/${path} — the repo is private and no readable authenticated gh is available (run gh auth login with read access to ${repo}, or pass a local checkout root instead)" >&2
	return 1
}

module_proto="$(sed -n 's/^[[:space:]]*const[[:space:]][[:space:]]*ProtocolVersion[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "${MODULE_DIR}/middleman.go" | head -n 1)"
if [ -z "$module_proto" ]; then
	echo "FAIL: this module declares no ProtocolVersion constant; the version handshake has nothing to announce" >&2
	exit 1
fi

agent="$(read_side "agent" "$AGENT_ROOT" "${AGENT_REPO}" "${AGENT_SUBDIR}" "${AGENT_REF}")"
daemon="$(read_side "daemon" "$DAEMON_ROOT" "${DAEMON_REPO}" "" "${DAEMON_REF}")"
agent_pin="$(echo "$agent" | cut -d' ' -f1)"
agent_proto="$(echo "$agent" | cut -d' ' -f2)"
daemon_pin="$(echo "$daemon" | cut -d' ' -f1)"
daemon_proto="$(echo "$daemon" | cut -d' ' -f2)"

status=0
if [ "$agent_pin" != "$daemon_pin" ]; then
	echo "FAIL the both-import pin: the agent pins ${MODULE} ${agent_pin} but the daemon pins ${daemon_pin}; the two sides would speak different protocols on one socket — bump both pins to the matching contracts version before any release" >&2
	status=1
fi
if [ "$agent_proto" != "$module_proto" ]; then
	echo "FAIL the agent's vendored copy declares ProtocolVersion ${agent_proto}, this module declares ${module_proto}; update the agent's pin to a contracts version carrying this protocol" >&2
	status=1
fi
if [ "$daemon_proto" != "$module_proto" ]; then
	echo "FAIL the daemon's vendored copy declares ProtocolVersion ${daemon_proto}, this module declares ${module_proto}; update the daemon's pin to a contracts version carrying this protocol" >&2
	status=1
fi
if [ "$status" -ne 0 ]; then
	echo "the test pin law: a failing protocol-compatibility test blocks a new version's release — refuse the release until the pins agree" >&2
	exit "$status"
fi
echo "both-import pin holds: the agent pins ${MODULE} ${agent_pin} and the daemon pins ${daemon_pin} (equal); both vendored copies carry ProtocolVersion ${module_proto} == this module's"
