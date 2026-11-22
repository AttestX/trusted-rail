//! Executes the compiled MIPS guest for differential testing. This binary has
//! no proving, network SDK or credential discovery dependency.
use p3_field::PrimeField32;
use sha2::{Digest, Sha256};
use trusted_rail::{rego::*, *};
use zkm_core_executor::{ExecutionError, Executor, Program};

#[path = "../../tests/support/mod.rs"]
mod cases;

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
    for case in cases::differential_cases() {
        let witness = case.witness();
        let native = evaluate_witness(&witness);
        match case.expected {
            Some(expected) => assert_eq!(
                RegorusEngine
                    .decode_public_values(native.as_ref().expect(case.name))
                    .unwrap()
                    .decision,
                expected,
                "{}",
                case.name
            ),
            None => assert!(native.is_err(), "{} must be rejected natively", case.name),
        }
        if let Some(dir) = &output {
            std::fs::write(dir.join(format!("{}.witness.json", case.name)), &witness).unwrap();
        }
        let mut executor = Executor::new(Program::from(&elf).unwrap(), Default::default());
        executor.max_cycles = Some(100_000_000);
        executor.state.input_stream.push(witness);
        let execution = executor.run_fast();
        match native {
            Ok(expected) => {
                execution.expect(case.name);
                assert_eq!(
                    executor.state.public_values_stream, expected,
                    "native/MIPS output differs for {}",
                    case.name
                );
            }
            Err(_) => {
                assert!(
                    matches!(execution, Err(ExecutionError::HaltWithNonZeroExitCode(1))),
                    "{}: expected guest rejection, got {execution:?}",
                    case.name
                );
                assert!(
                    executor.state.public_values_stream.is_empty(),
                    "{}: rejected guest must not publish a decision",
                    case.name
                );
            }
        }
        println!(
            "{}: native/MIPS agreement ({} cycles)",
            case.name, executor.state.global_clk
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
