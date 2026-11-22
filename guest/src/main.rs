#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let witness = zkm_zkvm::io::read_vec();
    let public_values =
        trusted_rail::rego::evaluate_witness(&witness).expect("invalid policy evaluation witness");
    zkm_zkvm::io::commit_slice(&public_values);
}
