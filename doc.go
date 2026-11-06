// Package contracts holds the neutral, signed job-spec wire contract
// for BMC runners: the job-spec schema, its validation battery, the
// canonical JSON encoding, Ed25519 signing and verification, the typed
// reason vocabulary with its class-to-disposition map, and the build
// cancel verb (the signed directive that stops a running attempt).
//
// It also holds the machine-side middleman protocol — the both-import
// wire the machine's agent and the runnermand daemon share over their
// local unix socket: the six-op interface and its request/reply
// envelopes (middleman.go, middleman_wire.go), the connect-time
// version handshake with its exact-match law and loud refusal document
// (handshake.go), the typed refusal vocabulary (refusal.go), and the
// golden wire fixtures the compat battery pins
// (testdata/golden/middleman). The custody law shapes the protocol's
// wire from day one: the signing seed is never a wire field, the
// registration token crosses only at install inside the named
// fresh-token field, one shot per delivery attempt.
//
// The module is open-source-safe by construction: it imports nothing
// private (a CI guard refuses any bare-metal-cloud module path other
// than this module itself), carries the Apache-2.0 publish kit from day
// one, and contains only generic runner technology — no organization,
// cluster, or product types.
//
// Consumers:
//
//   - the engine signs job specs before submitting them,
//   - the agent job-handler verifies and executes them,
//   - the Pool Manager verifies and admits them.
//
// The schema IS the contract. Golden wire fixtures under testdata/golden
// pin the exact canonical bytes and their deterministic signatures; a
// schema change that moves them fails the test suite, forcing an
// explicit, reviewed fixture update.
package contracts
