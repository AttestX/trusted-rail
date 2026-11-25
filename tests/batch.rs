use serde_json::{json, Value};
use trusted_rail::{rego::*, *};

const BUDGET: &str = r#"
package trusted
import rego.v1

total := input.state.spent + input.parameters.amount

default decision := {"decision": "deny", "reason_codes": ["over_budget"]}

decision := {
    "decision": "allow",
    "reason_codes": ["within_budget"],
    "next_state": {"spent": total},
} if total <= data.limit
"#;

fn policy() -> PolicyBundle {
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer":"user","policy_id":"budget","version":1,"sha256":""}),
        )
        .unwrap(),
        engine: engine_profile(),
        modules: [("budget.rego".into(), BUDGET.into())].into(),
        data: json!({"limit": 100}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    policy
}

fn spend(amount: u64, state: &Value, at: u64) -> EvaluationRequest {
    EvaluationRequest {
        execution: serde_json::from_value(json!({"namespace":"clawup","workload":"agent","allocation_id":"a1","lease_id":"l1","generation":1,"node_id":"n1"})).unwrap(),
        principal: "alice".into(),
        action_id: format!("spend-{at}"),
        operation: "trade.order".into(),
        resource: "exchange".into(),
        parameters: json!({"amount": amount}),
        context: json!({}),
        previous_state_root: state_root(state).unwrap(),
        state: Some(state.clone()),
        evaluated_at_unix: at,
        validity: serde_json::from_value(json!({"not_before": 100, "expires_at": 200})).unwrap(),
    }
}

/// Three spends of 40 against a limit of 100: allow, allow, deny.
fn run() -> (Vec<EvaluationRequest>, Vec<DecisionRecord>) {
    let policy = policy();
    let mut state = json!({"spent": 0});
    let (mut requests, mut records) = (Vec::new(), Vec::new());
    for at in [100, 101, 102] {
        let request = spend(40, &state, at);
        let moved = RegorusEngine.transition(&policy, &request).unwrap();
        if let Some(next) = moved.next_state {
            state = next;
        }
        requests.push(request);
        records.push(moved.record);
    }
    (requests, records)
}

#[test]
fn one_proof_covers_a_run_of_decisions() {
    let (requests, records) = run();
    let decisions: Vec<_> = records.iter().map(|record| record.decision).collect();
    assert_eq!(
        decisions,
        [Decision::Allow, Decision::Allow, Decision::Deny]
    );

    let witness = encode_batch_witness(&policy(), &requests).unwrap();
    let proven = decode_batch_public_values(&evaluate_witness(&witness).unwrap()).unwrap();
    // What the guest commits is what a verifier computes from the records it holds.
    assert_eq!(proven, batch_record(&records).unwrap());
    assert_eq!(proven.count, 3);
    assert_eq!(
        proven.previous_state_root,
        state_root(&json!({"spent": 0})).unwrap()
    );
    assert_eq!(
        proven.next_state_root,
        state_root(&json!({"spent": 80})).unwrap()
    );
    assert_eq!(proven.policy, records[0].policy);

    // The single-decision witness still yields a single record.
    let single = RegorusEngine
        .encode_witness(&policy(), &requests[0])
        .unwrap();
    let record = RegorusEngine
        .decode_public_values(&evaluate_witness(&single).unwrap())
        .unwrap();
    assert_eq!(record, records[0]);
    // The two results cannot be mistaken for each other.
    assert!(decode_batch_public_values(&evaluate_witness(&single).unwrap()).is_err());
    assert!(RegorusEngine
        .decode_public_values(&evaluate_witness(&witness).unwrap())
        .is_err());
}

#[test]
fn a_record_cannot_be_dropped_added_reordered_or_altered() {
    let (_, records) = run();
    let whole = batch_record(&records).unwrap();

    // Dropping the middle record breaks the chain.
    let dropped = [records[0].clone(), records[2].clone()];
    assert!(matches!(batch_record(&dropped), Err(Error::InvalidInput)));
    // So does swapping two.
    let swapped = [records[1].clone(), records[0].clone(), records[2].clone()];
    assert!(matches!(batch_record(&swapped), Err(Error::InvalidInput)));
    // Leaving the last one off still chains, but it is a different, shorter run.
    let shorter = batch_record(&records[..2]).unwrap();
    assert_eq!(shorter.count, 2);
    assert_ne!(shorter.records_sha256, whole.records_sha256);
    // A deny rewritten as an allow no longer matches the proof.
    let mut altered = records.clone();
    altered[2].decision = Decision::Allow;
    assert_ne!(
        batch_record(&altered).unwrap().records_sha256,
        whole.records_sha256
    );
    // Records of another execution do not belong in the run.
    let mut foreign = records.clone();
    foreign[1].execution.workload = "other-agent".into();
    assert!(matches!(batch_record(&foreign), Err(Error::InvalidInput)));
    assert!(matches!(batch_record(&[]), Err(Error::InvalidInput)));
}

#[test]
fn a_batch_witness_that_skips_or_reorders_a_request_is_refused() {
    let (requests, _) = run();
    let prove = |requests: &[EvaluationRequest]| {
        evaluate_witness(&encode_batch_witness(&policy(), requests).unwrap())
    };
    assert!(prove(&requests).is_ok());
    // Skipping the second spend: the third no longer starts where the first ended.
    assert!(prove(&[requests[0].clone(), requests[2].clone()]).is_err());
    // Out of time order.
    assert!(prove(&[requests[1].clone(), requests[0].clone()]).is_err());
    assert!(prove(&[]).is_err());
    // One request that cannot be evaluated fails the run; it is never skipped.
    let mut forged = requests.clone();
    forged[1].state = Some(json!({"spent": 0}));
    assert!(prove(&forged).is_err());
    let too_many = vec![requests[2].clone(); MAX_BATCH + 1];
    assert!(evaluate_batch(&policy(), &too_many).is_err());
}
