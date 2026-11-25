use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use trusted_contracts::ExecutionIdentity;
use trusted_rail::{
    action::Action,
    rego::{
        decode_batch_public_values, engine_profile, evaluate_witness, policy_digest, state_root,
    },
    Decision, Error, PolicyBundle,
};
use trusted_rail_ledger::{Attempt, Ledger, ProofVerifier, NO_STATE_ROOT};

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

/// Stands in for a proof system: a receipt is the digest of the public values.
struct Digest32;
impl ProofVerifier for Digest32 {
    fn verify(&self, public_values: &[u8], receipt: &[u8]) -> trusted_rail::Result<()> {
        if receipt == Sha256::digest(public_values).as_slice() {
            Ok(())
        } else {
            Err(Error::Rejected)
        }
    }
}
fn receipt(public_values: &[u8]) -> Vec<u8> {
    Sha256::digest(public_values).to_vec()
}

fn policy(limit: u64) -> PolicyBundle {
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer":"user","policy_id":"budget","version":1,"sha256":""}),
        )
        .unwrap(),
        engine: engine_profile(),
        modules: [("budget.rego".into(), BUDGET.into())].into(),
        data: json!({ "limit": limit }),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    policy
}

fn agent(name: &str) -> ExecutionIdentity {
    serde_json::from_value(json!({"namespace":"clawup","workload":name,"allocation_id":"a1","lease_id":"l1","generation":1,"node_id":"n1"})).unwrap()
}

fn spend(
    ledger: &Ledger,
    who: &ExecutionIdentity,
    id: &str,
    amount: u64,
    at: u64,
) -> trusted_rail::Result<Decision> {
    let action = Action {
        operation: "trade.order".into(),
        resource: "exchange".into(),
        parameters: json!({ "amount": amount }),
    };
    let attempt = Attempt {
        execution: who.clone(),
        principal: "alice".into(),
        action_id: id.into(),
        context: json!({}),
        evaluated_at_unix: at,
        validity: serde_json::from_value(json!({"not_before": 100, "expires_at": 1000})).unwrap(),
    };
    Ok(ledger.decide(action, attempt)?.decision)
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn open(dir: &tempfile::TempDir) -> Ledger {
    Ledger::open(&dir.path().join("ledger.db"), Arc::new(Digest32)).unwrap()
}
fn fresh() -> Value {
    json!({"spent": 0})
}

#[test]
fn a_budget_is_kept_across_decisions_and_restarts() {
    let dir = private_dir();
    let who = agent("trader");
    let ledger = open(&dir);
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    // Activating again with the same values changes nothing.
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    assert_eq!(spend(&ledger, &who, "1", 40, 100).unwrap(), Decision::Allow);
    assert_eq!(spend(&ledger, &who, "2", 40, 101).unwrap(), Decision::Allow);
    // The same action is never decided twice.
    assert!(matches!(
        spend(&ledger, &who, "2", 1, 102),
        Err(Error::Conflict)
    ));
    // Nor can an agent restart its budget by activating again.
    assert!(matches!(
        ledger.activate(&who, &policy(100), Some(&fresh())),
        Err(Error::Conflict)
    ));
    drop(ledger);

    let ledger = open(&dir);
    assert_eq!(spend(&ledger, &who, "3", 40, 102).unwrap(), Decision::Deny);
    assert_eq!(spend(&ledger, &who, "4", 20, 103).unwrap(), Decision::Allow);
    let head = ledger.head(&who).unwrap();
    assert_eq!(head.state, Some(json!({"spent": 100})));
    assert_eq!(head.state_root, state_root(&json!({"spent": 100})).unwrap());
    assert_eq!((head.decisions, head.proven, head.active), (4, 0, true));
    // Time does not run backwards along a chain.
    assert!(matches!(
        spend(&ledger, &who, "5", 0, 50),
        Err(Error::Conflict)
    ));
    // An action that cannot be evaluated is refused and leaves no record.
    assert!(spend(&ledger, &who, "6", 0, 5000).is_err());
    assert_eq!(ledger.head(&who).unwrap().decisions, 4);
}

#[test]
fn each_agent_has_its_own_chain() {
    let dir = private_dir();
    let ledger = open(&dir);
    let (one, two) = (agent("one"), agent("two"));
    ledger.activate(&one, &policy(50), Some(&fresh())).unwrap();
    ledger.activate(&two, &policy(50), Some(&fresh())).unwrap();
    assert_eq!(spend(&ledger, &one, "1", 50, 100).unwrap(), Decision::Allow);
    assert_eq!(spend(&ledger, &one, "2", 1, 100).unwrap(), Decision::Deny);
    assert_eq!(spend(&ledger, &two, "1", 50, 100).unwrap(), Decision::Allow);
    // An agent nobody activated is refused.
    assert!(matches!(
        spend(&ledger, &agent("stranger"), "1", 1, 100),
        Err(Error::Rejected)
    ));
}

#[test]
fn decisions_are_proven_in_order_and_only_once() {
    let dir = private_dir();
    let who = agent("trader");
    let ledger = open(&dir);
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    assert!(ledger.next_batch(&who, 10).unwrap().is_none());
    for (id, at) in [("1", 100), ("2", 101), ("3", 102)] {
        spend(&ledger, &who, id, 40, at).unwrap();
    }

    let batch = ledger.next_batch(&who, 2).unwrap().unwrap();
    assert_eq!(batch.summary.count, 2);
    assert_eq!(
        batch.summary.previous_state_root,
        state_root(&fresh()).unwrap()
    );
    // The witness, run as the guest runs it, commits exactly the summary.
    let public = evaluate_witness(&batch.witness).unwrap();
    assert_eq!(decode_batch_public_values(&public).unwrap(), batch.summary);

    // A wrong receipt, and a proof of a run the ledger does not hold, are refused.
    assert!(matches!(
        ledger.record_proof(&who, &batch.summary, b"not a proof"),
        Err(Error::Rejected)
    ));
    let mut other = batch.summary.clone();
    other.next_state_root = "1".repeat(64);
    assert!(matches!(
        ledger.record_proof(&who, &other, &receipt(&public)),
        Err(Error::Conflict)
    ));
    ledger
        .record_proof(&who, &batch.summary, &receipt(&public))
        .unwrap();
    // The same proof is not accepted twice.
    assert!(matches!(
        ledger.record_proof(&who, &batch.summary, &receipt(&public)),
        Err(Error::Conflict)
    ));
    assert_eq!(ledger.head(&who).unwrap().proven, 2);

    // The rest follows from where the first proof ended.
    let rest = ledger.next_batch(&who, 10).unwrap().unwrap();
    assert_eq!(rest.summary.count, 1);
    assert_eq!(rest.records[0].decision, Decision::Deny);
    assert_eq!(
        rest.summary.previous_state_root,
        batch.summary.next_state_root
    );
    let public = evaluate_witness(&rest.witness).unwrap();
    ledger
        .record_proof(&who, &rest.summary, &receipt(&public))
        .unwrap();
    assert!(ledger.next_batch(&who, 10).unwrap().is_none());

    let proofs = ledger.proofs(&who).unwrap();
    assert_eq!(proofs.len(), 2);
    assert_eq!(proofs[0].0.next_state_root, proofs[1].0.previous_state_root);
}

#[test]
fn a_new_policy_keeps_what_was_spent() {
    let dir = private_dir();
    let who = agent("trader");
    let ledger = open(&dir);
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    assert_eq!(spend(&ledger, &who, "1", 80, 100).unwrap(), Decision::Allow);
    assert_eq!(spend(&ledger, &who, "2", 80, 101).unwrap(), Decision::Deny);
    ledger.set_policy(&who, &policy(200)).unwrap();
    assert_eq!(spend(&ledger, &who, "3", 80, 102).unwrap(), Decision::Allow);
    assert_eq!(
        ledger.head(&who).unwrap().state,
        Some(json!({"spent": 160}))
    );
    // A proof covers one policy, so the run is cut where the policy changed.
    let first = ledger.next_batch(&who, 10).unwrap().unwrap();
    assert_eq!(
        (first.summary.count, &first.summary.policy),
        (2, &policy(100).policy)
    );
    let public = evaluate_witness(&first.witness).unwrap();
    ledger
        .record_proof(&who, &first.summary, &receipt(&public))
        .unwrap();
    let second = ledger.next_batch(&who, 10).unwrap().unwrap();
    assert_eq!(
        (second.summary.count, &second.summary.policy),
        (1, &policy(200).policy)
    );
    // A policy whose digest does not match its content is not accepted.
    let mut forged = policy(300);
    forged.data = json!({"limit": 1000000});
    assert!(matches!(
        ledger.set_policy(&who, &forged),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn a_revoked_agent_stays_revoked_and_can_still_be_proven() {
    let dir = private_dir();
    let who = agent("trader");
    let ledger = open(&dir);
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    spend(&ledger, &who, "1", 40, 100).unwrap();
    ledger.revoke(&who).unwrap();
    assert!(matches!(
        spend(&ledger, &who, "2", 1, 101),
        Err(Error::Rejected)
    ));
    assert!(matches!(
        ledger.activate(&who, &policy(100), Some(&fresh())),
        Err(Error::Rejected)
    ));
    assert!(matches!(
        ledger.set_policy(&who, &policy(200)),
        Err(Error::Rejected)
    ));
    assert!(!ledger.head(&who).unwrap().active);
    assert_eq!(
        ledger.next_batch(&who, 10).unwrap().unwrap().summary.count,
        1
    );

    // A revocation that arrives before the activation still holds.
    let late = agent("late");
    ledger.revoke(&late).unwrap();
    assert!(matches!(
        ledger.activate(&late, &policy(100), Some(&fresh())),
        Err(Error::Rejected)
    ));
}

#[test]
fn an_agent_that_moves_carries_its_state() {
    let (old_dir, new_dir) = (private_dir(), private_dir());
    let old_node = open(&old_dir);
    let before = agent("trader");
    old_node
        .activate(&before, &policy(100), Some(&fresh()))
        .unwrap();
    spend(&old_node, &before, "1", 80, 100).unwrap();
    let head = old_node.head(&before).unwrap();
    old_node.revoke(&before).unwrap();

    // Another node, another generation, the same spent budget.
    let new_node = open(&new_dir);
    let mut after = before.clone();
    after.generation = 2;
    after.node_id = "n2".into();
    new_node
        .activate(&after, &policy(100), head.state.as_ref())
        .unwrap();
    assert_eq!(new_node.head(&after).unwrap().state_root, head.state_root);
    assert_eq!(
        spend(&new_node, &after, "1", 80, 200).unwrap(),
        Decision::Deny
    );
}

#[test]
fn a_policy_without_state_has_a_fixed_root() {
    let dir = private_dir();
    let ledger = open(&dir);
    let who = agent("stateless");
    let mut allow_all = policy(0);
    allow_all.modules = [(
        "allow.rego".into(),
        "package trusted\nimport rego.v1\ndecision := {\"decision\": \"allow\", \"reason_codes\": [\"ok\"]}\n".into(),
    )]
    .into();
    allow_all.policy.sha256 = policy_digest(&allow_all).unwrap();
    ledger.activate(&who, &allow_all, None).unwrap();
    assert_eq!(spend(&ledger, &who, "1", 1, 100).unwrap(), Decision::Allow);
    let head = ledger.head(&who).unwrap();
    assert_eq!(
        (head.state_root.as_str(), head.state),
        (NO_STATE_ROOT, None)
    );
}

#[test]
fn the_ledger_file_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_dir();
    open(&dir);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Ledger::open(&dir.path().join("ledger.db"), Arc::new(Digest32)),
        Err(Error::InvalidInput)
    ));
}

/// Runs this test binary again as another process that opens the same ledger.
fn other_process(dir: &tempfile::TempDir, task: &str) -> String {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "another_process_opening_the_ledger_loses_nothing",
            "--nocapture",
        ])
        .env("LEDGER_OTHER_PROCESS", dir.path())
        .env("LEDGER_OTHER_TASK", task)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn another_process_opening_the_ledger_loses_nothing() {
    let who = agent("trader");
    if let Some(path) = std::env::var_os("LEDGER_OTHER_PROCESS") {
        let ledger = Ledger::open(
            &std::path::Path::new(&path).join("ledger.db"),
            Arc::new(Digest32),
        )
        .unwrap();
        if std::env::var("LEDGER_OTHER_TASK").unwrap() == "count" {
            println!("decisions={}", ledger.head(&who).unwrap().decisions);
        }
        return;
    }
    let dir = private_dir();
    let ledger = open(&dir);
    ledger.activate(&who, &policy(100), Some(&fresh())).unwrap();
    spend(&ledger, &who, "1", 10, 100).unwrap();
    // A second service starts on the same file and exits, as a failed restart does.
    other_process(&dir, "open");
    spend(&ledger, &who, "2", 10, 101).unwrap();
    assert!(other_process(&dir, "count").contains("decisions=2"));
}
