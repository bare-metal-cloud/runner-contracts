# Security Policy

## Supported versions

The module is released from `main`; every tagged version receives
security fixes. Consumers should track the latest tag.

## Reporting a vulnerability

Report suspected vulnerabilities in the wire schema, the canonical
encoding, or the Ed25519 signing and verification logic to
**security@bare-metal-cloud.com**.

Please include a description of the issue, the steps to reproduce it,
and (if possible) a proof of concept against this module's test battery.
We acknowledge reports within two business days and will coordinate a
fix and disclosure timeline with the reporter.

Please do not open a public GitHub issue for an unreported
vulnerability.

## Scope

In scope: anything in this module that a malicious document could use to
bypass validation (for example a document that verifies but decodes to
different content, a validation law that can be evaded, or a strict-decode
refusal that can be tricked).

Out of scope: the platforms that consume this module (the engine, the
agent, the Pool Manager). Report those through the channels documented in
each repository.
