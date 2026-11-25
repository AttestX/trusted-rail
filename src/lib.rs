//! Deterministic rule-engine and authorization-ledger contracts.
//!
//! Native and proving integrations share the same pinned Regorus evaluator.
//! Proof generation and cryptographic verification belong to trusted-shim.

pub mod action;
pub mod rego;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use trusted_contracts::{ExecutionIdentity, PolicyRef, Validity};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid policy or evaluation input")]
    InvalidInput,
    #[error("unsupported evaluator or capability")]
    Unsupported,
    #[error("evaluation could not complete")]
    EvaluationFailed,
    #[error("authorization rejected, expired or revoked")]
    Rejected,
    #[error("authorization state changed or grant already consumed")]
    Conflict,
    #[error("authorization ledger unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineProfile {
    pub implementation: String,
    pub version: String,
    pub capabilities_sha256: String,
}

/// Already approved by the policy owner; the digest binds modules, data and
/// evaluator profile. This record does not authenticate its own origin.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub policy: PolicyRef,
    pub engine: EngineProfile,
    pub modules: BTreeMap<String, String>,
    pub data: Value,
}

/// Principal, context and time must come from authenticated authoritative inputs,
/// not from an agent's claimed identity or intent. Do not include raw credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRequest {
    pub execution: ExecutionIdentity,
    pub principal: String,
    pub action_id: String,
    pub operation: String,
    pub resource: String,
    pub parameters: Value,
    pub context: Value,
    pub previous_state_root: String,
    /// The authorization state the policy reads as `input.state`, such as what
    /// a budget has already spent. When present it must hash to
    /// `previous_state_root` (`rego::state_root`), so the ledger that holds the
    /// root, not the caller, decides which state is current. Absent, the policy
    /// keeps no state and the root is carried through unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    pub evaluated_at_unix: u64,
    pub validity: Validity,
}

/// An error or unsupported capability is never an allow decision. ApprovalRequired
/// is a workflow outcome and must not dispatch an action before fresh admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    ApprovalRequired,
}

/// Proposed public output of native evaluation and a policy proof guest.
/// A decision proves rule evaluation, not execution of external side effects.
/// Records form a chain: one's `next_state_root` is the next one's
/// `previous_state_root`, so a record cannot be dropped or reordered unnoticed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub execution: ExecutionIdentity,
    pub policy: PolicyRef,
    pub engine: EngineProfile,
    pub action_id: String,
    pub request_sha256: String,
    pub context_sha256: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub decision: Decision,
    pub reason_codes: Vec<String>,
    pub validity: Validity,
}

/// Public output of one proof over a run of decisions for one execution under
/// one policy. A verifier that holds the records recomputes `records_sha256`
/// (`rego::batch_record`); the roots place the run in the execution's chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRecord {
    pub execution: ExecutionIdentity,
    pub policy: PolicyRef,
    pub engine: EngineProfile,
    pub count: u32,
    /// Where the first record starts and the last one ends.
    pub previous_state_root: String,
    pub next_state_root: String,
    pub records_sha256: String,
}

/// No network, wall-clock reads or randomness. State changes only as the policy's
/// own `next_state`, committed in the record's `next_state_root`.
/// Implementations reuse an upstream engine and reject unsupported policies.
pub trait RuleEngine: Send + Sync {
    fn evaluate(
        &self,
        policy: &PolicyBundle,
        request: &EvaluationRequest,
    ) -> Result<DecisionRecord>;
}

/// Only serialization for a pinned proof program. Decoding public values does not
/// verify a proof; trusted-shim must first authenticate them cryptographically.
pub trait PolicyProofCodec: Send + Sync {
    fn encode_witness(&self, policy: &PolicyBundle, request: &EvaluationRequest)
        -> Result<Vec<u8>>;
    fn decode_public_values(&self, verified_public_values: &[u8]) -> Result<DecisionRecord>;
}

/// Opaque single-use credential. Intentionally has no Debug/Serialize impl.
pub struct ExecutionGrant {
    pub id: String,
    pub credential: Vec<u8>,
    pub execution: ExecutionIdentity,
    pub request_sha256: String,
    pub validity: Validity,
}

/// The grant interface of a ledger: a proven decision is reserved, then consumed
/// once immediately before dispatch. Whoever enforces hosts the ledger, never the
/// workload being judged. The `trusted-rail-ledger` crate in this repository holds
/// the storage for policies, state roots and the decision chain.
#[async_trait]
pub trait AuthorizationLedger: Send + Sync {
    /// In one transaction: check policy/revocation/current roots, validate required
    /// proof evidence, reserve cumulative budget and issue a single-use grant.
    /// PolicyEngine execution requires a verified proof. The optional argument is
    /// retained for source compatibility; implementations must reject None.
    async fn reserve(
        &self,
        decision: &DecisionRecord,
        proof_evidence: Option<&[u8]>,
    ) -> Result<ExecutionGrant>;

    /// Atomically consume against the exact execution and request immediately
    /// before dispatch. A stale lease, changed context, replay or outage fails.
    async fn consume(
        &self,
        grant: &ExecutionGrant,
        execution: &ExecutionIdentity,
        request_sha256: &str,
    ) -> Result<()>;
}
