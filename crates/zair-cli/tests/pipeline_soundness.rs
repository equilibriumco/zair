//! Soundness checks for tampered proof/submission pipeline artifacts.

#![allow(
    clippy::indexing_slicing,
    reason = "Test code intentionally indexes JSON fields directly"
)]

mod test_utils;

use test_utils::pipeline_harness::{
    cached, ensure_claim_run, flip_hex_byte, load_json, message_path, proofs_path, submission_path,
    verify_proof_failure_stderr, verify_signature_failure_stderr, write_tampered,
};

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected stderr to contain '{needle}', got:\n{haystack}"
    );
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_sapling_zkproof() {
    ensure_claim_run("native");
    let mut data = load_json(&proofs_path("native"));
    flip_hex_byte(&mut data["sapling_proofs"][0]["zkproof"], 0);
    let tampered = write_tampered("tampered-proof-sapling-zkproof.json", &data);
    let stderr = verify_proof_failure_stderr("native", &tampered);
    assert_contains(&stderr, "proofs failed verification");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_sapling_cv() {
    ensure_claim_run("native");
    let mut data = load_json(&proofs_path("native"));
    flip_hex_byte(&mut data["sapling_proofs"][0]["cv"], 0);
    let tampered = write_tampered("tampered-proof-sapling-cv.json", &data);
    let stderr = verify_proof_failure_stderr("native", &tampered);
    assert_contains(&stderr, "proofs failed verification");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_sapling_nullifier() {
    ensure_claim_run("native");
    let mut data = load_json(&proofs_path("native"));
    flip_hex_byte(&mut data["sapling_proofs"][0]["airdrop_nullifier"], 0);
    let tampered = write_tampered("tampered-proof-sapling-nullifier.json", &data);
    let stderr = verify_proof_failure_stderr("native", &tampered);
    assert_contains(&stderr, "proofs failed verification");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_orchard_zkproof() {
    ensure_claim_run("native");
    let mut data = load_json(&proofs_path("native"));
    flip_hex_byte(&mut data["orchard_proofs"][0]["zkproof"], 0);
    let tampered = write_tampered("tampered-proof-orchard-zkproof.json", &data);
    let stderr = verify_proof_failure_stderr("native", &tampered);
    assert_contains(&stderr, "proofs failed verification");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_orchard_cv() {
    ensure_claim_run("native");
    let mut data = load_json(&proofs_path("native"));
    flip_hex_byte(&mut data["orchard_proofs"][0]["cv"], 0);
    let tampered = write_tampered("tampered-proof-orchard-cv.json", &data);
    let stderr = verify_proof_failure_stderr("native", &tampered);
    assert_contains(&stderr, "proofs failed verification");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_spend_auth_sig() {
    ensure_claim_run("native");
    let mut data = load_json(&submission_path("native"));
    flip_hex_byte(&mut data["sapling"][0]["spend_auth_sig"], 0);
    let tampered = write_tampered("tampered-submission-sapling-sig.json", &data);
    let stderr = verify_signature_failure_stderr("native", &tampered, &message_path());
    assert!(
        stderr.contains("submission signatures failed verification") ||
            stderr.contains("Invalid Sapling signature encoding"),
        "expected signature verification failure, got:\n{stderr}"
    );
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_tamper_orchard_spend_auth_sig() {
    ensure_claim_run("native");
    let mut data = load_json(&submission_path("native"));
    flip_hex_byte(&mut data["orchard"][0]["spend_auth_sig"], 0);
    let tampered = write_tampered("tampered-submission-orchard-sig.json", &data);
    let stderr = verify_signature_failure_stderr("native", &tampered, &message_path());
    assert!(
        stderr.contains("submission signatures failed verification") ||
            stderr.contains("Invalid Orchard signature encoding"),
        "expected signature verification failure, got:\n{stderr}"
    );
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_wrong_message() {
    ensure_claim_run("native");
    let wrong_message = cached("tampered-wrong-message.bin");
    std::fs::write(&wrong_message, b"wrong-message").expect("write wrong message");

    let stderr =
        verify_signature_failure_stderr("native", &submission_path("native"), &wrong_message);
    assert_contains(&stderr, "message hash mismatch");
}

#[test]
#[ignore = "Full pipeline: requires network access + heavy computation"]
fn soundness_duplicate_nullifier() {
    ensure_claim_run("native");
    let mut data = load_json(&submission_path("native"));
    let first = data["sapling"][0].clone();
    data["sapling"]
        .as_array_mut()
        .expect("sapling must be an array")
        .push(first);
    let tampered = write_tampered("tampered-submission-duplicate-nullifier.json", &data);
    let stderr = verify_signature_failure_stderr("native", &tampered, &message_path());
    assert_contains(&stderr, "Duplicate Sapling signed claim entry");
}
