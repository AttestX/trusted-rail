# trusted-rail

Deterministic Rego policy evaluation shared by native admission and a Ziren proof
guest. The guest executes the complete pinned Regorus interpreter against the
policy and request; its public output commits to the resulting decision. The
witness cannot supply a precomputed decision.

## Evaluation contract

`RegorusEngine` implements `RuleEngine` and `PolicyProofCodec`, using Regorus
0.15.0 with only `no_std` enabled. No extensions are installed. Randomness, time,
HTTP, UUID and runtime-query builtins are unavailable. CI audits Cargo feature
unification for both Regorus and serde_json; downstream binaries must run the
same audit. It rejects features such as `arbitrary_precision` and `preserve_order`
and remains enforced under Python optimization. The approved guest ELF
and verifying key also pin the actual compiled program, beyond its profile label.

Policies use ordinary Rego v1 and return `data.trusted.decision`:

```rego
package trusted
import rego.v1

default decision := {"decision": "deny", "reason_codes": ["not_permitted"]}
decision := {"decision": "allow", "reason_codes": ["permitted"]} if {
    input.operation == "read"
    input.principal in data.readers
}
```

The result must contain exactly `decision` (`allow`, `deny`, `approval_required`)
and `reason_codes`. Undefined rules, evaluation errors and malformed outputs are
errors, never allow. Approval requires a new authorization, not automatic dispatch.
A fresh interpreter isolates each evaluation from prior requests.

`policy_digest` binds issuer, policy ID/version, engine profile, modules and data.
The gateway computes and approves it before distribution. `request_digest` binds
all execution, principal, action, resource, parameter, context and validity fields.
Inputs use a versioned, sorted-object JSON encoding with integer JSON numbers;
applications use strings for decimal amounts. This is not RFC 8785. Witnesses and
public values must use this exact encoding; ambiguous re-encodings are rejected.
The reserved object key `$serde_json::private::Number` is rejected at every depth
in policy data and request inputs to prevent Regorus interpreting an object as
a number.

This first profile evaluates an authorization-state snapshot and preserves its
state root. It does not pretend to prove a ledger write. The central
`AuthorizationLedger` must validate the proof, current policy/context/lease,
reserve cumulative budgets atomically and consume an exact-request grant once.
The retained optional proof argument must reject `None` on policy execution paths.

## What is proved

`guest/src/main.rs` reads the policy/request witness, calls `evaluate_witness`
(which runs Regorus), and commits the complete `DecisionRecord` with a policy
proof domain tag. Native admission computes the expected public bytes through the
same implementation. trusted-shim submits the guest and witness to the proof
network and verifies the receipt against these bytes and an approved program key.
It never treats a completed job or a matching hash as a valid proof.

Authenticated policy ownership, input provenance, wall-clock freshness, central
budget concurrency and non-bypassable runtime enforcement remain separate
obligations. A valid decision proof does not establish external effects. Witnesses
are visible to the remote proving operator; do not put provider credentials in them.
OpenShell's native isolation policies and enforcement retain their upstream form.

## Validation and artifacts

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python3 scripts/check_engine_features.py
python3 -O -m unittest discover -s tests -p 'test_*.py'
```

Build with the Ziren MIPS toolchain (tested with `rustc +zkm` 1.94.0-dev):

```sh
export CARGO_TARGET_DIR=/absolute/path/outside-repository/build
scripts/build_guest.sh
cargo run --locked --manifest-path guest-check/Cargo.toml -- \
  "$CARGO_TARGET_DIR/mipsel-zkm-zkvm-elf/release/trusted-rail-policy-guest" \
  /absolute/path/outside-repository/artifacts
```

The checker executes the actual MIPS ELF and compares allow/deny public bytes
with native evaluation. It optionally writes synthetic witnesses and a program
manifest, deriving the verifying key through upstream static machine setup. An
existing output manifest is invalidated before validation; the replacement is
published atomically only after all comparisons pass. It
contains no network client or proof generator. The key-digest packing follows
Ziren's `HashableKey` at the pinned revision; cryptographic primitives are reused.
Keep the ELF, manifest, witnesses and proofs outside tracked files.

Migration remains blocked by Regorus 0.15.0's platform-dependent large-index
conversions in `substring` and `array.slice`: native admission is 64-bit and the
MIPS guest is 32-bit. The current differential smoke test does not establish
equivalence for every policy. Restricting input integers alone would not cover
large literals or computed indexes inside Rego policies.

Ziren guest, executor and verifier revisions must match the Fleet prover image.
The real network acceptance test must register this ELF as its own Fleet proof app,
start its prover through Fleet, then use that app's StageService endpoint. The
Fleet control-plane URL is not itself a proof endpoint. The shim repository has
the remote submission/verification example. Local tests are not a remote proof.

Rail is a library and proof guest, not an independently deployed server. Fleet
and shim use it for strict startup admission and preflight action decisions;
preflight receipts are generated asynchronously by the proof network. Build the
guest as an immutable ELF/manifest artifact for the remote worker image. Runtime
images are published by Fleet/shim; there is no Rail daemon image. TEE attestation
verification is a separate proof program. See [shim](https://github.com/attestx/trusted-shim)
and [Fleet](https://github.com/ProjectZKM/zkm-fleet) for orchestration.
