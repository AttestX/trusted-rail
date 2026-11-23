use serde_json::json;
use trusted_rail::{rego::*, *};

pub fn fixture() -> (PolicyBundle, EvaluationRequest) {
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer":"gateway","policy_id":"tools","version":1,"sha256":""}),
        )
        .unwrap(),
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
        execution: serde_json::from_value(json!({"namespace":"clawup","workload":"agent","allocation_id":"a1","lease_id":"l1","generation":1,"node_id":"n1"})).unwrap(),
        principal: "alice".into(),
        action_id: "request-1".into(),
        operation: "read".into(),
        resource: "workspace".into(),
        parameters: json!({"bytes":42}),
        context: json!({"remaining_bytes":100}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: 100,
        validity: serde_json::from_value(json!({"not_before":100,"expires_at":200})).unwrap(),
    };
    (policy, request)
}

pub struct Case {
    pub name: &'static str,
    pub policy: PolicyBundle,
    pub request: EvaluationRequest,
    pub expected: Option<Decision>,
}

impl Case {
    // Also encode invalid cases without passing through the host's validator.
    pub fn witness(&self) -> Vec<u8> {
        let mut value = json!({
            "domain":"trusted-rail.policy-witness.v1",
            "policy":self.policy,"request":self.request
        });
        value.sort_all_objects();
        serde_json::to_vec(&value).unwrap()
    }
}

pub fn differential_cases() -> Vec<Case> {
    let (policy, request) = fixture();
    let mut cases = vec![Case {
        name: "read",
        policy: policy.clone(),
        request: request.clone(),
        expected: Some(Decision::Allow),
    }];
    let mut denied = request.clone();
    denied.operation = "delete".into();
    cases.push(Case {
        name: "delete",
        policy: policy.clone(),
        request: denied,
        expected: Some(Decision::Deny),
    });

    for (name, condition) in [
        ("arithmetic-and-data", "input.principal in data.readers; input.parameters.bytes * 2 + 1 < input.context.remaining_bytes"),
        ("unicode-substring", r#"substring("a好😀z", 1, 2) == "好😀""#),
        ("substring-input-offset", r#"substring("abcd", input.parameters.offset, 2) == """#),
        ("substring-computed-offset", r#"offset := 4294967295 + 1; substring("abcd", offset, 2) == """#),
        ("substring-max-offset", r#"substring("abcd", 9223372036854775807, 2) == """#),
        ("substring-large-length", r#"substring("a好😀z", 0, 4294967296) == "a好😀z""#),
        ("substring-negative-length", r#"substring("a好😀z", 1, -1) == "好😀z""#),
        ("array-input-stop", "array.slice([0,1,2,3], 0, input.parameters.stop) == [0,1,2,3]"),
        ("array-large-start", "array.slice([0,1,2,3], 4294967296, 4294967299) == []"),
        ("array-max-stop", "array.slice([0,1,2,3], 0, 9223372036854775807) == [0,1,2,3]"),
        ("array-negative-bounds", "array.slice([0,1,2,3], -1, 2) == [0,1]; array.slice([0,1,2,3], 0, -1) == []"),
        ("array-input-lookup", "a := [11,22]; not a[input.parameters.offset]"),
        ("array-computed-lookup", "a := [11,22]; offset := 4294967295 + 1; not a[offset]"),
        ("array-max-lookup", "a := [11,22]; not a[18446744073709551615]"),
        ("object-large-key", "obj := {4294967296: 11}; obj[4294967296] == 11"),
    ] {
        let mut p = policy.clone();
        p.modules = [("test.rego".into(), format!("package trusted\nimport rego.v1\ndefault decision := {{\"decision\":\"deny\",\"reason_codes\":[]}}\ndecision := {{\"decision\":\"allow\",\"reason_codes\":[]}} if {{ {condition} }}"))].into();
        p.policy.sha256 = policy_digest(&p).unwrap();
        let mut r = request.clone();
        if name.contains("input") {
            r.parameters["offset"] = json!(4294967296u64);
            r.parameters["stop"] = json!(4294967299u64);
        }
        cases.push(Case { name, policy: p, request: r, expected: Some(Decision::Allow) });
    }

    for (name, output, expected) in [
        (
            "approval",
            r#"{"decision":"approval_required","reason_codes":["review"]}"#,
            Some(Decision::ApprovalRequired),
        ),
        (
            "invalid-output",
            r#"{"decision":"allow","reason_codes":[],"override":true}"#,
            None,
        ),
        ("builtin-error", r#"substring("abcd", -1, 2)"#, None),
    ] {
        let mut p = policy.clone();
        p.modules = [(
            "test.rego".into(),
            format!("package trusted\ndecision := {output}"),
        )]
        .into();
        p.policy.sha256 = policy_digest(&p).unwrap();
        cases.push(Case {
            name,
            policy: p,
            request: request.clone(),
            expected,
        });
    }
    let mut expired = request.clone();
    expired.evaluated_at_unix = expired.validity.expires_at;
    cases.push(Case {
        name: "expired",
        policy: policy.clone(),
        request: expired,
        expected: None,
    });
    let mut ambiguous = request.clone();
    ambiguous.parameters["offset"] = json!({"$serde_json::private::Number":"1.5"});
    cases.push(Case {
        name: "reserved-number-key",
        policy: policy.clone(),
        request: ambiguous,
        expected: None,
    });
    let mut legacy = policy;
    use sha2::{Digest, Sha256};
    legacy.engine.capabilities_sha256 = hex::encode(Sha256::digest(b"trusted-rail.regorus.v1;regorus=0.15.0;features=no_std;rego=v1;entry=data.trusted.decision;strict=true;json=sorted-integer-v1;state=read-only"));
    legacy.policy.sha256 = policy_digest(&legacy).unwrap();
    cases.push(Case {
        name: "legacy-profile",
        policy: legacy,
        request,
        expected: None,
    });
    cases
}
