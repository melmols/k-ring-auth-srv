extern crate rand;
extern crate bellman;
use bellman::{Circuit, Scalar};
use bellman::groth16::{
    create_random_proof,
    generate_random_parameters,
    Parameters,
    Proof,
    verify_proof,
};
use bellman::pairing::{
    bn256::{Bn256, G1},
};
use rand::thread_rng;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

fn trusted_setup() -> (Parameters<Bn256>, Proof<Bn256>) {
    let mut rng = thread_rng();
    let circuit = <dyn Circuit<Scalar<Bn256>>>::new("keyring");
    let params = generate_random_parameters(&circuit, &mut rng).unwrap();
    let proof = create_random_proof(&params, &circuit, &mut rng).unwrap();
    (params, proof)
}

fn generate_proof(password: &[u8], params: &Parameters<Bn256>) -> Proof<Bn256> {
    let mut rng = thread_rng();
    create_random_proof(params, &mut rng, |p| p.input(password)).unwrap()
}

fn verify_password(proof: &Proof<Bn256>, params: &Parameters<Bn256>, password: &[u8]) -> bool {
    verify_proof(params, proof, |p| p.input(password)).is_ok()
}

fn authenticate_user(password: &[u8]) -> bool {
    let (params, proof) = trusted_setup();
    let generated_proof = generate_proof(password, &params);
    verify_password(&generated_proof, &params, password)
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