extern crate bellman;
extern crate rand;
extern crate bls12_381;
use bellman::groth16;
use bellman::groth16::{Parameters, Proof};
use bellman::{domain::Scalar, Circuit};
use bls12_381::Bls12;
use rand::thread_rng;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

fn build_trusted_setup() -> (Parameters<Bls12>, Proof<Bls12>) {
    let mut rng = thread_rng();
    let circuit = <dyn Circuit<Scalar<Bls12>>>::new("keyring");
    let params = groth16::generate_random_parameters(circuit, &mut rng).unwrap();
    let proof = groth16::create_random_proof(circuit, &params, &mut rng).unwrap();  // FF: this proof never gets used anywhere
    (params, proof)
}

fn generate_proof(password: &[u8], params: &Parameters<Bls12>) -> Proof<Bls12> {
    let mut rng = thread_rng();
    groth16::create_random_proof(|p| p.input(password), &*params, &mut rng).unwrap()
}

fn verify_password(params: &Parameters<Bls12>, proof: &Proof<Bls12>, password: &[u8]) -> bool {
    let pvk = groth16::prepare_verifying_key(&params.vk);
    groth16::verify_proof(&pvk, &proof, |p| p.input(password)).is_ok()
}

fn authenticate_user(password: &[u8]) -> bool {
    let (params, proof) = build_trusted_setup();
    let generated_proof = generate_proof(&password, &params);
    verify_password(&params, &generated_proof, &password)
}

fn main() {
    println!("Enter password:");
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim().as_bytes();

    if authenticate_user(password) {
        println!("Authentication successful!");

        let file = File::open("file.txt").unwrap();
        let reader = BufReader::new(file);
        for line in reader.lines() {
            println!("{}", line.unwrap());
        }
    } else {
        println!("Authentication failed!");
    }
}
