//! Executes the compiled MIPS guest for differential testing. This binary has
//! no proving, network SDK or credential discovery dependency.
use p3_field::PrimeField32;
use sha2::{Digest, Sha256};
use trusted_rail::{rego::*, *};
use zkm_core_executor::{Executor, Program};

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .expect("usage: trusted-rail-guest-check ELF");
    let output = std::env::args_os().nth(2).map(std::path::PathBuf::from);
    if let Some(dir) = &output {
        std::fs::create_dir_all(dir).unwrap();
        // Invalidate a previous result before checking this candidate. A failed
        // run must not leave an apparently approved manifest in the output dir.
        match std::fs::remove_file(dir.join("program.json")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("invalidate previous manifest: {error}"),
        }
    }
    let elf = std::fs::read(path).expect("read ELF");
    for operation in ["read", "delete"] {
        let mut policy:PolicyBundle=serde_json::from_value(serde_json::json!({
            "policy":{"issuer":"gateway","policy_id":"tools","version":1,"sha256":""},
            "engine":engine_profile(),"data":{},"modules":{"p.rego":"package trusted\nimport rego.v1\ndefault decision := {\"decision\":\"deny\",\"reason_codes\":[]}\ndecision := {\"decision\":\"allow\",\"reason_codes\":[]} if { input.operation == \"read\" }"}
        })).unwrap();
        policy.policy.sha256 = policy_digest(&policy).unwrap();
        let request:EvaluationRequest=serde_json::from_value(serde_json::json!({
            "execution":{"namespace":"tenant","workload":"agent","allocation_id":"a","lease_id":"l","generation":1,"node_id":"n"},
            "principal":"alice","action_id":"action","operation":operation,"resource":"workspace","parameters":{},"context":{},"previous_state_root":"0".repeat(64),"evaluated_at_unix":100,"validity":{"not_before":100,"expires_at":200}
        })).unwrap();
        let witness = RegorusEngine.encode_witness(&policy, &request).unwrap();
        let native = evaluate_witness(&witness).unwrap();
        if let Some(dir) = &output {
            std::fs::write(dir.join(format!("{operation}.witness.json")), &witness).unwrap();
        }
        let mut executor = Executor::new(Program::from(&elf).unwrap(), Default::default());
        executor.max_cycles = Some(100_000_000);
        executor.state.input_stream.push(witness);
        executor.run_fast().expect("MIPS guest execution");
        assert_eq!(
            executor.state.public_values_stream, native,
            "native/MIPS output differs for {operation}"
        );
        println!(
            "{operation}: native/MIPS output identical ({} cycles)",
            executor.state.global_clk
        );
    }
    // Publish only after every native/MIPS comparison has succeeded.
    if let Some(dir) = &output {
        // Upstream machine setup only commits the static program tables. This
        // does not initialize a prover, execute a witness or generate a proof.
        let machine = zkm_core_machine::MipsAir::machine(
            zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2::default(),
        );
        let (_, vk) = machine.setup(&Program::from(&elf).unwrap());
        // The key packing below follows Ziren's HashableKey::hash_koalabear
        // and koalabears_to_bn254 at the pinned revision. Hashing itself reuses
        // zkm-primitives, not a separately implemented cryptographic primitive.
        let mut inputs = vk.commit[0].to_vec();
        inputs.push(vk.pc_start);
        inputs.extend(vk.initial_global_cumulative_sum.0.x.0);
        inputs.extend(vk.initial_global_cumulative_sum.0.y.0);
        let mut packed = num_bigint::BigUint::from(0u32);
        for word in zkm_primitives::poseidon2_hash(inputs) {
            packed = (packed << 31) + num_bigint::BigUint::from(word.as_canonical_u32());
        }
        let hash = format!("{:0>64}", packed.to_str_radix(16));
        let manifest = serde_json::json!({"ziren_revision":"c9988a098d92bc55a85ca9307c470d1f97be3337","program_sha256":hex::encode(Sha256::digest(&elf)),"program_vkey_hash":format!("0x{hash}"),"verifying_key_sha256":hex::encode(Sha256::digest(hex::decode(&hash).unwrap()))});
        std::fs::write(
            dir.join("program.json.tmp"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::rename(dir.join("program.json.tmp"), dir.join("program.json")).unwrap();
    }
}
