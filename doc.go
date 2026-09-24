// Package contracts holds the neutral, signed job-spec wire contract
// for BMC runners: the job-spec schema, its validation battery, the
// canonical JSON encoding, Ed25519 signing and verification, and the
// typed reason vocabulary with its class-to-disposition map.
//
// The module is open-source-safe by construction: it imports nothing
// private (a CI guard refuses any bare-metal-cloud/backend or
// bare-metal-cloud/agent module path), carries the Apache-2.0 publish
// kit from day one, and contains only generic runner technology — no
// organization, cluster, or product types.
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
