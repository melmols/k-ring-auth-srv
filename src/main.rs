extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate rand;

use bulletproofs::r1cs::{LinearCombination, R1CSProof, Variable};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;

fn main() {
    // Generate the Pedersen generators
    let pc_gens = PedersenGens::default();

    // Generate the bulletproof generator
    let bp_gens = BulletproofGens::new(128, 1);

    // The username to authenticate
    let username = "alice";

    // The password for the user
    let password = "correct horse battery staple";

    // Generate the Pedersen commitment for the username
    let username_commitment = CompressedRistretto::from_scalar(Scalar::from(username.as_bytes()));

    // Generate the Pedersen commitment for the password
    let password_commitment = CompressedRistretto::from_scalar(Scalar::from(password.as_bytes()));

    // Create the R1CS proof
    let mut prover_transcript = bulletproofs::r1cs::ProverTranscript::new(&pc_gens);

    // Create the variables for the username and password commitments
    let (username_var, password_var) = prover_transcript.commit(vec![username_commitment, password_commitment]);

    // Create the constraints for the authentication
    let username_correct = LinearCombination::from(username_var) - LinearCombination::from(Scalar::from(username.as_bytes()));
    let password_correct = LinearCombination::from(password_var) - LinearCombination::from(Scalar::from(password.as_bytes()));
    prover_transcript.constrain(username_correct);
    prover_transcript.constrain(password_correct);

    // Create the proof
    let proof = prover_transcript.prove(&bp_gens);

    // Verify the proof
    let mut verifier_transcript = bulletproofs::r1cs::VerifierTranscript::new(&pc_gens);
    assert!(proof.verify(&mut verifier_transcript, &vec![username_commitment, password_commitment], &vec![Scalar::from(username.as_bytes()), Scalar::from(password.as_bytes())])

    // If the verification succeeds, the authentication is successful
    println!("Authentication successful!");
}