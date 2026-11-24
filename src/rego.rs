//! The same evaluator is linked into the native adapter and the Ziren guest.
//! Nothing in the witness supplies a precomputed decision.
use crate::*;
use sha2::{Digest, Sha256};

pub const MAX_WITNESS_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PUBLIC_BYTES: usize = 64 * 1024;
pub const MAX_STATE_BYTES: usize = 32 * 1024;
const PROFILE: &str = "trusted-rail.regorus.v3;regorus=0.15.0;patch=portable-indices-v1;features=no_std;rego=v1;entry=data.trusted.decision;strict=true;json=sorted-integer-v1;state=transition-v1";

#[derive(Clone, Copy, Default)]
pub struct RegorusEngine;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
    domain: String,
    policy: PolicyBundle,
    request: EvaluationRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicValues {
    domain: String,
    record: DecisionRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleOutput {
    decision: Decision,
    reason_codes: Vec<String>,
    #[serde(default)]
    next_state: Option<Value>,
}

/// A decision and the state it leaves behind. The record commits only to the
/// state's root; the ledger stores `next_state` for the next evaluation.
#[derive(Clone, Debug)]
pub struct Transition {
    pub record: DecisionRecord,
    pub next_state: Option<Value>,
}

/// Explicit, versioned encoding shared by host and guest. Object keys are sorted;
/// floating-point JSON is rejected (use strings for application decimal values).
/// This is not a claim of RFC 8785 compatibility.
pub fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| Error::InvalidInput)?;
    fn check(value: &Value) -> Result<()> {
        match value {
            Value::Number(n) if !n.is_i64() && !n.is_u64() => return Err(Error::InvalidInput),
            Value::Array(values) => values.iter().try_for_each(check)?,
            Value::Object(values) => {
                // Regorus treats this serde_json sentinel as a number, even
                // though the committed JSON value is an object. Reject it at
                // every depth so evaluation and commitment see the same type.
                if values.contains_key("$serde_json::private::Number") {
                    return Err(Error::InvalidInput);
                }
                values.values().try_for_each(check)?;
            }
            _ => (),
        }
        Ok(())
    }
    check(&value)?;
    value.sort_all_objects();
    serde_json::to_vec(&value).map_err(|_| Error::InvalidInput)
}

pub fn commitment(domain: &str, value: &impl Serialize) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(canonical_bytes(value)?);
    Ok(hex::encode(hash.finalize()))
}

pub fn engine_profile() -> EngineProfile {
    EngineProfile {
        implementation: "regorus".into(),
        version: "0.15.0".into(),
        capabilities_sha256: hex::encode(Sha256::digest(PROFILE.as_bytes())),
    }
}

/// Calculate before the gateway approves/signs the immutable policy revision.
/// The digest excludes only its own field; issuer, id and version are included.
pub fn policy_digest(policy: &PolicyBundle) -> Result<String> {
    commitment(
        "trusted-rail.policy.v1",
        &serde_json::json!({
            "issuer": policy.policy.issuer, "id": policy.policy.policy_id,
            "version": policy.policy.version, "engine": policy.engine,
            "modules": policy.modules, "data": policy.data,
        }),
    )
}

/// The root a ledger holds for an authorization state.
pub fn state_root(state: &Value) -> Result<String> {
    if canonical_bytes(state)?.len() > MAX_STATE_BYTES {
        return Err(Error::InvalidInput);
    }
    commitment("trusted-rail.state.v1", state)
}

pub fn request_digest(request: &EvaluationRequest) -> Result<String> {
    commitment("trusted-rail.request.v1", request)
}

pub(crate) fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl RuleEngine for RegorusEngine {
    fn evaluate(
        &self,
        policy: &PolicyBundle,
        request: &EvaluationRequest,
    ) -> Result<DecisionRecord> {
        Ok(self.transition(policy, request)?.record)
    }
}

impl RegorusEngine {
    /// Evaluate, and return the state the policy moved to with the record that
    /// commits to it. Only an allow decision may change the state.
    pub fn transition(
        &self,
        policy: &PolicyBundle,
        request: &EvaluationRequest,
    ) -> Result<Transition> {
        if policy.engine != engine_profile() {
            return Err(Error::Unsupported);
        }
        if canonical_bytes(policy)?.len() > 1024 * 1024
            || canonical_bytes(request)?.len() > 64 * 1024
            || policy.modules.is_empty()
            || policy.modules.len() > 32
            || policy.policy.sha256 != policy_digest(policy)?
            || !digest(&request.previous_state_root)
            || !valid_text(&policy.policy.issuer)
            || !valid_text(&policy.policy.policy_id)
            || policy.policy.version == 0
            || ![
                &request.principal,
                &request.action_id,
                &request.operation,
                &request.resource,
                &request.execution.namespace,
                &request.execution.workload,
                &request.execution.node_id,
                &request.execution.allocation_id,
                &request.execution.lease_id,
            ]
            .iter()
            .all(|v| valid_text(v))
            || request.execution.generation == 0
            || request.evaluated_at_unix < request.validity.not_before
            || request.evaluated_at_unix >= request.validity.expires_at
        {
            return Err(Error::InvalidInput);
        }
        // The policy must read the state the ledger holds, not one the caller chose.
        if let Some(state) = &request.state {
            if state_root(state)? != request.previous_state_root {
                return Err(Error::InvalidInput);
            }
        }
        // A fresh engine for each evaluation prevents cached data or extensions
        // leaking across requests. No host extensions, clock or randomness.
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(true);
        engine.set_gather_prints(true);
        for (name, source) in &policy.modules {
            if !valid_text(name) {
                return Err(Error::InvalidInput);
            }
            engine
                .add_policy(name.clone(), source.clone())
                .map_err(|_| Error::InvalidInput)?;
        }
        engine
            .add_data_json(
                &String::from_utf8(canonical_bytes(&policy.data)?)
                    .map_err(|_| Error::InvalidInput)?,
            )
            .map_err(|_| Error::InvalidInput)?;
        engine
            .set_input_json(
                &String::from_utf8(canonical_bytes(request)?).map_err(|_| Error::InvalidInput)?,
            )
            .map_err(|_| Error::InvalidInput)?;
        let output = engine
            .eval_rule("data.trusted.decision".into())
            .map_err(|_| Error::EvaluationFailed)?;
        let output = output.to_json_str().map_err(|_| Error::EvaluationFailed)?;
        if output.len() > MAX_PUBLIC_BYTES {
            return Err(Error::EvaluationFailed);
        }
        let output: RuleOutput =
            serde_json::from_str(&output).map_err(|_| Error::EvaluationFailed)?;
        if output.reason_codes.len() > 16 || !output.reason_codes.iter().all(|v| valid_text(v)) {
            return Err(Error::EvaluationFailed);
        }
        let next_state_root = match (&output.next_state, &request.state, output.decision) {
            (None, _, _) => request.previous_state_root.clone(),
            // A refused or pending action spends nothing, and a policy without
            // state has none to move.
            (Some(next), Some(_), Decision::Allow) => {
                state_root(next).map_err(|_| Error::EvaluationFailed)?
            }
            _ => return Err(Error::EvaluationFailed),
        };
        let record = DecisionRecord {
            execution: request.execution.clone(),
            policy: policy.policy.clone(),
            engine: policy.engine.clone(),
            action_id: request.action_id.clone(),
            request_sha256: request_digest(request)?,
            context_sha256: commitment("trusted-rail.context.v1", &request.context)?,
            previous_state_root: request.previous_state_root.clone(),
            next_state_root,
            decision: output.decision,
            reason_codes: output.reason_codes,
            validity: request.validity.clone(),
        };
        Ok(Transition {
            record,
            next_state: output.next_state,
        })
    }
}

impl PolicyProofCodec for RegorusEngine {
    fn encode_witness(
        &self,
        policy: &PolicyBundle,
        request: &EvaluationRequest,
    ) -> Result<Vec<u8>> {
        let bytes = canonical_bytes(&Witness {
            domain: "trusted-rail.policy-witness.v1".into(),
            policy: policy.clone(),
            request: request.clone(),
        })?;
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(bytes)
    }
    fn decode_public_values(&self, bytes: &[u8]) -> Result<DecisionRecord> {
        if bytes.len() > MAX_PUBLIC_BYTES {
            return Err(Error::InvalidInput);
        }
        let values: PublicValues =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
        if values.domain != "trusted-rail.policy-result.v1" || canonical_bytes(&values)? != bytes {
            return Err(Error::InvalidInput);
        }
        Ok(values.record)
    }
}

pub fn encode_public_values(record: &DecisionRecord) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(&PublicValues {
        domain: "trusted-rail.policy-result.v1".into(),
        record: record.clone(),
    })?;
    if bytes.len() > MAX_PUBLIC_BYTES {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}

/// Guest entry: parse the actual policy/request, execute Regorus, commit result.
/// A valid proof of this program proves evaluation, not just hash computation.
pub fn evaluate_witness(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_WITNESS_BYTES {
        return Err(Error::InvalidInput);
    }
    let witness: Witness = serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
    if witness.domain != "trusted-rail.policy-witness.v1" || canonical_bytes(&witness)? != bytes {
        return Err(Error::InvalidInput);
    }
    encode_public_values(&RegorusEngine.evaluate(&witness.policy, &witness.request)?)
}
