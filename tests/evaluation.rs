use serde_json::json;
use trusted_contracts::{ExecutionIdentity, PolicyRef, Validity};
use trusted_rail::{rego::*, *};

fn fixture() -> (PolicyBundle, EvaluationRequest) {
    let mut policy = PolicyBundle {
        policy: PolicyRef {
            issuer: "gateway".into(),
            policy_id: "tools".into(),
            version: 1,
            sha256: String::new(),
        },
        engine: engine_profile(),
        modules: [(
            "tools.rego".into(),
            r#"
package trusted
import rego.v1
default decision := {"decision": "deny", "reason_codes": ["not_permitted"]}
decision := {"decision": "allow", "reason_codes": ["permitted"]} if {
    input.operation == "read"
    input.principal in data.readers
    input.parameters.bytes <= input.context.remaining_bytes
}
"#
            .into(),
        )]
        .into(),
        data: json!({"readers":["alice"]}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    let request = EvaluationRequest {
        execution: ExecutionIdentity {
            namespace: "clawup".into(),
            workload: "agent".into(),
            allocation_id: "a1".into(),
            lease_id: "l1".into(),
            generation: 1,
            node_id: "n1".into(),
        },
        principal: "alice".into(),
        action_id: "request-1".into(),
        operation: "read".into(),
        resource: "workspace".into(),
        parameters: json!({"bytes":42}),
        context: json!({"remaining_bytes":100}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: 100,
        validity: Validity {
            not_before: 100,
            expires_at: 200,
        },
    };
    (policy, request)
}

#[test]
fn guest_executes_the_same_policy_and_commits_the_complete_decision() {
    let (policy, request) = fixture();
    let native = RegorusEngine.evaluate(&policy, &request).unwrap();
    assert_eq!(native.decision, Decision::Allow);
    let witness = RegorusEngine.encode_witness(&policy, &request).unwrap();
    let public = evaluate_witness(&witness).unwrap();
    assert_eq!(RegorusEngine.decode_public_values(&public).unwrap(), native);
    assert_eq!(public, encode_public_values(&native).unwrap());
    let mut changed = request.clone();
    changed.operation = "delete".into();
    let denied = RegorusEngine.evaluate(&policy, &changed).unwrap();
    assert_eq!(denied.decision, Decision::Deny);
    assert_ne!(denied.request_sha256, native.request_sha256);
    let mut changed = request;
    changed.context["remaining_bytes"] = json!(1);
    assert_eq!(
        RegorusEngine.evaluate(&policy, &changed).unwrap().decision,
        Decision::Deny
    );
}

#[test]
fn policy_content_profile_and_expiry_are_checked() {
    let (mut policy, mut request) = fixture();
    policy.data["readers"] = json!(["mallory"]);
    assert!(RegorusEngine.evaluate(&policy, &request).is_err());
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    assert_eq!(
        RegorusEngine.evaluate(&policy, &request).unwrap().decision,
        Decision::Deny
    );
    policy.engine.capabilities_sha256 = "0".repeat(64);
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    assert!(matches!(
        RegorusEngine.evaluate(&policy, &request),
        Err(Error::Unsupported)
    ));
    let (policy, _) = fixture();
    request.evaluated_at_unix = request.validity.expires_at;
    assert!(RegorusEngine.evaluate(&policy, &request).is_err());
    request.evaluated_at_unix = request.validity.not_before - 1;
    assert!(RegorusEngine.evaluate(&policy, &request).is_err());
}

#[test]
fn external_and_nondeterministic_builtins_fail_closed() {
    for expression in [
        "rand.intn(\"x\", 10)",
        "time.now_ns()",
        "http.send({\"method\":\"GET\",\"url\":\"https://example.invalid\"})",
        "opa.runtime()",
        "uuid.rfc4122(\"x\")",
    ] {
        let (mut policy, request) = fixture();
        policy.modules.insert("tools.rego".into(),format!("package trusted\nimport rego.v1\ndecision := {{\"decision\":\"allow\",\"reason_codes\":[]}} if {{ x := {expression}; x != null }}"));
        policy.policy.sha256 = policy_digest(&policy).unwrap();
        assert!(
            RegorusEngine.evaluate(&policy, &request).is_err(),
            "{expression}"
        );
    }
}

#[test]
fn invalid_outputs_errors_and_unknown_fields_are_not_allow() {
    for output in [
        "true",
        "{}",
        "{\"decision\":\"allow\",\"reason_codes\":[],\"override\":true}",
        "{\"decision\":\"unknown\",\"reason_codes\":[]}",
        "1 / 0",
    ] {
        let (mut policy, request) = fixture();
        policy.modules.insert(
            "tools.rego".into(),
            format!("package trusted\ndecision := {output}"),
        );
        policy.policy.sha256 = policy_digest(&policy).unwrap();
        assert!(
            RegorusEngine.evaluate(&policy, &request).is_err(),
            "{output}"
        );
    }
    let (mut policy, request) = fixture();
    policy.modules.insert("tools.rego".into(),"package trusted\ndecision := {\"decision\":\"approval_required\",\"reason_codes\":[\"review\"]}".into());
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    assert_eq!(
        RegorusEngine.evaluate(&policy, &request).unwrap().decision,
        Decision::ApprovalRequired
    );
}

#[test]
fn canonical_encoding_rejects_ambiguous_or_oversized_witnesses() {
    let (policy, request) = fixture();
    let witness = RegorusEngine.encode_witness(&policy, &request).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&witness).unwrap();
    value["decision"] = json!("allow");
    assert!(evaluate_witness(&canonical_bytes(&value).unwrap()).is_err());
    assert!(evaluate_witness(&[b' '; MAX_WITNESS_BYTES + 1]).is_err());
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&witness).unwrap())
            .unwrap();
    assert!(evaluate_witness(&pretty).is_err());
    assert!(canonical_bytes(&json!({"amount":1.5})).is_err());
    assert_eq!(
        canonical_bytes(&json!({"z":1,"a":{"b":2,"a":3}})).unwrap(),
        b"{\"a\":{\"a\":3,\"b\":2},\"z\":1}"
    );
}

#[test]
fn every_execution_and_request_field_is_bound() {
    let (policy, request) = fixture();
    let original = RegorusEngine.evaluate(&policy, &request).unwrap();
    for (path, replacement) in [
        ("/execution/namespace", json!("other-tenant")),
        ("/execution/workload", json!("other-agent")),
        ("/execution/allocation_id", json!("a2")),
        ("/execution/lease_id", json!("l2")),
        ("/execution/generation", json!(2)),
        ("/execution/node_id", json!("n2")),
        ("/principal", json!("bob")),
        ("/action_id", json!("request-2")),
        ("/operation", json!("delete")),
        ("/resource", json!("other-workspace")),
        ("/parameters/bytes", json!(43)),
        ("/context/remaining_bytes", json!(101)),
        ("/previous_state_root", json!("1".repeat(64))),
        ("/evaluated_at_unix", json!(101)),
        ("/validity/not_before", json!(99)),
        ("/validity/expires_at", json!(201)),
    ] {
        let mut values = serde_json::to_value(&request).unwrap();
        *values.pointer_mut(path).unwrap() = replacement;
        let changed: EvaluationRequest = serde_json::from_value(values).unwrap();
        let different = RegorusEngine.evaluate(&policy, &changed).unwrap();
        assert_ne!(original.request_sha256, different.request_sha256, "{path}");
        assert_ne!(
            encode_public_values(&original).unwrap(),
            encode_public_values(&different).unwrap(),
            "{path}"
        );
    }
}

#[test]
fn reserved_json_number_objects_are_rejected_before_evaluation() {
    for text in ["1", "1.5", "1e3", "-0"] {
        let magic = json!({"$serde_json::private::Number": text});
        for value in [
            magic.clone(),
            json!([{"nested":magic.clone()}]),
            json!({"$serde_json::private::Number":text,"other":true}),
        ] {
            assert!(matches!(canonical_bytes(&value), Err(Error::InvalidInput)));
        }
        let (policy, request) = fixture();
        for field in ["parameters", "context"] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = json!({"nested":[magic.clone()]});
            let changed: EvaluationRequest = serde_json::from_value(value).unwrap();
            assert!(matches!(
                RegorusEngine.evaluate(&policy, &changed),
                Err(Error::InvalidInput)
            ));
            assert!(RegorusEngine.encode_witness(&policy, &changed).is_err());
            // Also exercise a manually encoded witness, bypassing the host codec.
            let raw = serde_json::to_vec(&json!({"domain":"trusted-rail.policy-witness.v1","policy":policy,"request":changed})).unwrap();
            assert!(matches!(evaluate_witness(&raw), Err(Error::InvalidInput)));
        }
        let mut policy = policy;
        policy.data = json!({"nested":[magic]});
        assert!(matches!(policy_digest(&policy), Err(Error::InvalidInput)));
        assert!(matches!(
            RegorusEngine.evaluate(&policy, &request),
            Err(Error::InvalidInput)
        ));
    }
}
