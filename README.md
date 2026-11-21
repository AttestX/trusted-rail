# trusted-rail

Rust interfaces for rule evaluation and verifiable authorization. This framework
does not implement an evaluator or a new policy language. Concrete implementation
is deferred until the framework PR is reviewed.

## Boundaries

- `RuleEngine` evaluates an approved policy against an authenticated request.
- `PolicyProofCodec` encodes the witness and decodes authenticated public values.
  It does not verify cryptographic proofs.
- `AuthorizationLedger` is a central gateway interface: atomic budget reservation,
  current policy/context checks and single-use grant consumption.
- `trusted-shim` calls these interfaces, mediates actual operations, submits to
  the proof network and verifies receipts. The router handles service access.

Policy ownership, version approval, revocation and cumulative authorization remain
at the central gateway. Deploying an evaluator at each node does not give each node
an independent budget. Database transactions should implement ledger atomicity.

Native evaluation and the proving guest must use the same evaluator version,
capability profile, policy and canonical request encoding. The explicit timestamp
is supplied as authenticated input. Unexpected evaluation errors fail closed.
`approval_required` does not authorize execution. Policy decisions and physical
execution outcomes are distinct claims.

## Reuse decision to validate

First evaluate [Regorus](https://github.com/microsoft/regorus), the Rust Rego
interpreter used by existing confidential-computing policy integrations. Reuse its
parser/evaluator and upstream conformance tests. Do not write a parallel DSL or a
simplified evaluator for proofs. [Cedar](https://github.com/cedar-policy/cedar) is an
alternative if the needed authorization model is a better fit; no engine is pinned
by this framework PR.

Regorus feature selection alone is not a determinism proof: its builtin registry
includes `rand.intn`, and other profiles can enable time, HTTP or runtime queries.
The implementation must enforce an explicit deterministic capability profile and
prove native/guest equivalence for that profile. `no_std` support does not establish
compatibility or acceptable proof cost on the selected ZK VM.

OpenShell filesystem/process/network policies retain their upstream representation
and enforcement. The central policy version can bind these and rail's business
authorization policy; this framework proposes no automatic translation between
policy languages and no OpenShell fork.

## Reviewable contracts

`PolicyBundle` binds a `PolicyRef` to engine profile, modules and policy data.
`EvaluationRequest` binds principal, action, parameters, context, execution and
previous authorization state. `DecisionRecord` carries both state roots and the
request commitments. Shared execution types come from `trusted-contracts` in
`trusted-data-router`; the dependency is pinned to its framework commit.

All are proposed v0.1 interfaces. Structs do not themselves check signatures or
canonicalization. The later implementation must authenticate input provenance,
select canonical encoding, bind proof program/verifying key and enforce limits.
Raw provider credentials must not be placed in witnesses. The remote proving
operator receives the witness; zero knowledge alone does not hide it from them.

## Next acceptance tests, after review

Native allow/deny/error handling; action and policy substitution; deterministic
native/guest results; two-node budget races; expiry, revocation and grant replay;
real policy proof submission/verification through the proof network. No local ZK
prover is started. These behavioral tests are not claimed by this framework.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
