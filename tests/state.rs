use serde_json::{json, Value};
use trusted_rail::{rego::*, *};

const DAY: u64 = 86_400;

/// A daily budget: the state is what has been spent since the day began.
const BUDGET: &str = r#"
package trusted
import rego.v1

day := input.evaluated_at_unix - (input.evaluated_at_unix % 86400)

spent := input.state.spent if input.state.day == day
spent := 0 if input.state.day != day

total := spent + input.parameters.amount

default decision := {"decision": "deny", "reason_codes": ["over_budget"]}

decision := {
    "decision": "allow",
    "reason_codes": ["within_budget"],
    "next_state": {"day": day, "spent": total},
} if {
    input.parameters.amount > 0
    total <= data.daily_limit
}
"#;

fn policy(source: &str) -> PolicyBundle {
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer":"user","policy_id":"budget","version":1,"sha256":""}),
        )
        .unwrap(),
        engine: engine_profile(),
        modules: [("budget.rego".into(), source.into())].into(),
        data: json!({"daily_limit": 100}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    policy
}

fn spend(amount: u64, state: Option<&Value>, at: u64) -> EvaluationRequest {
    EvaluationRequest {
        execution: serde_json::from_value(json!({"namespace":"clawup","workload":"agent","allocation_id":"a1","lease_id":"l1","generation":1,"node_id":"n1"})).unwrap(),
        principal: "alice".into(),
        action_id: format!("spend-{at}-{amount}"),
        operation: "trade.order".into(),
        resource: "exchange".into(),
        parameters: json!({"amount": amount}),
        context: json!({}),
        previous_state_root: state.map_or_else(|| "0".repeat(64), |state| state_root(state).unwrap()),
        state: state.cloned(),
        evaluated_at_unix: at,
        validity: serde_json::from_value(json!({"not_before": at, "expires_at": at + 60})).unwrap(),
    }
}

#[test]
fn a_budget_is_spent_along_a_chain_of_records() {
    let policy = policy(BUDGET);
    let mut state = json!({"day": 0, "spent": 0});
    let mut records = Vec::new();
    for amount in [40, 40] {
        let moved = RegorusEngine
            .transition(&policy, &spend(amount, Some(&state), 100))
            .unwrap();
        assert_eq!(moved.record.decision, Decision::Allow);
        let next = moved.next_state.expect("an allowed spend moves the state");
        assert_eq!(
            moved.record.previous_state_root,
            state_root(&state).unwrap()
        );
        assert_eq!(moved.record.next_state_root, state_root(&next).unwrap());
        assert_ne!(
            moved.record.next_state_root,
            moved.record.previous_state_root
        );
        state = next;
        records.push(moved.record);
    }
    assert_eq!(state, json!({"day": 0, "spent": 80}));
    // Each record starts where the one before it ended.
    assert_eq!(records[0].next_state_root, records[1].previous_state_root);

    // The third spend would pass the limit: refused, and nothing is spent.
    let refused = RegorusEngine
        .transition(&policy, &spend(40, Some(&state), 100))
        .unwrap();
    assert_eq!(refused.record.decision, Decision::Deny);
    assert!(refused.next_state.is_none());
    assert_eq!(
        refused.record.next_state_root,
        refused.record.previous_state_root
    );

    // A new day starts a new budget.
    let tomorrow = RegorusEngine
        .transition(&policy, &spend(40, Some(&state), DAY + 100))
        .unwrap();
    assert_eq!(tomorrow.record.decision, Decision::Allow);
    assert_eq!(tomorrow.next_state, Some(json!({"day": DAY, "spent": 40})));
}

#[test]
fn the_policy_reads_only_the_state_the_root_commits_to() {
    let policy = policy(BUDGET);
    let spent = json!({"day": 0, "spent": 80});
    // The caller presents a fresh budget against the root of the spent one.
    let mut forged = spend(40, Some(&spent), 100);
    forged.state = Some(json!({"day": 0, "spent": 0}));
    assert!(matches!(
        RegorusEngine.transition(&policy, &forged),
        Err(Error::InvalidInput)
    ));
    // The state is part of the request: another state is another request.
    let digest = |state: &Value| request_digest(&spend(40, Some(state), 100)).unwrap();
    assert_ne!(digest(&spent), digest(&json!({"day": 0, "spent": 79})));
}

#[test]
fn only_an_allow_with_state_may_move_it() {
    let state = json!({"day": 0, "spent": 0});
    let deny_and_move = policy(
        r#"
package trusted
import rego.v1
decision := {"decision": "deny", "reason_codes": ["no"], "next_state": {"day": 0, "spent": 0}}
"#,
    );
    assert!(matches!(
        RegorusEngine.transition(&deny_and_move, &spend(1, Some(&state), 100)),
        Err(Error::EvaluationFailed)
    ));
    let move_without_state = policy(
        r#"
package trusted
import rego.v1
decision := {"decision": "allow", "reason_codes": ["ok"], "next_state": {"spent": 1}}
"#,
    );
    assert!(matches!(
        RegorusEngine.transition(&move_without_state, &spend(1, None, 100)),
        Err(Error::EvaluationFailed)
    ));
    // A state that cannot be committed (floating point) is not an allow.
    let fractional = policy(
        r#"
package trusted
import rego.v1
decision := {"decision": "allow", "reason_codes": ["ok"], "next_state": {"spent": 0.5}}
"#,
    );
    assert!(matches!(
        RegorusEngine.transition(&fractional, &spend(1, Some(&state), 100)),
        Err(Error::EvaluationFailed)
    ));
}

#[test]
fn a_policy_without_state_carries_the_root_through() {
    let stateless = policy(
        r#"
package trusted
import rego.v1
decision := {"decision": "allow", "reason_codes": ["ok"]}
"#,
    );
    let request = spend(1, None, 100);
    let moved = RegorusEngine.transition(&stateless, &request).unwrap();
    assert!(moved.next_state.is_none());
    assert_eq!(moved.record.next_state_root, request.previous_state_root);
    // A request without state encodes as it did before the field existed.
    let encoded = String::from_utf8(canonical_bytes(&request).unwrap()).unwrap();
    assert!(!encoded.contains("\"state\""));
}

#[test]
fn the_guest_commits_the_same_transition() {
    let policy = policy(BUDGET);
    let state = json!({"day": 0, "spent": 0});
    let request = spend(40, Some(&state), 100);
    let native = RegorusEngine.transition(&policy, &request).unwrap();
    let witness = RegorusEngine.encode_witness(&policy, &request).unwrap();
    let proven = RegorusEngine
        .decode_public_values(&evaluate_witness(&witness).unwrap())
        .unwrap();
    assert_eq!(proven, native.record);
    assert_eq!(
        proven.next_state_root,
        state_root(&json!({"day": 0, "spent": 40})).unwrap()
    );
}

#[test]
fn a_policy_approved_for_the_read_only_profile_is_refused() {
    use sha2::{Digest, Sha256};
    let mut old = policy(BUDGET);
    old.engine.capabilities_sha256 = hex::encode(Sha256::digest(b"trusted-rail.regorus.v2;regorus=0.15.0;patch=portable-indices-v1;features=no_std;rego=v1;entry=data.trusted.decision;strict=true;json=sorted-integer-v1;state=read-only"));
    old.policy.sha256 = policy_digest(&old).unwrap();
    assert!(matches!(
        RegorusEngine.transition(&old, &spend(1, None, 100)),
        Err(Error::Unsupported)
    ));
}
