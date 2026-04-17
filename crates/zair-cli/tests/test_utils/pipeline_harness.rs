#![allow(
    dead_code,
    clippy::indexing_slicing,
    reason = "Test helpers intentionally use direct indexing for concise assertions"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use zair_core::schema::config::{AirdropConfiguration, ValueCommitmentScheme};

const CACHE: &str = "target/test-pipeline";
const MESSAGE: &[u8] = b"test-pipeline";

fn test_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn test_network() -> String {
    std::env::var("ZAIR_TEST_NETWORK").unwrap_or_else(|_| "testnet".to_owned())
}

fn test_height() -> String {
    test_env("ZAIR_TEST_HEIGHT")
}

fn test_birthday() -> String {
    test_env("ZAIR_TEST_BIRTHDAY")
}

fn test_lightwalletd() -> String {
    std::env::var("ZAIR_TEST_LIGHTWALLETD")
        .unwrap_or_else(|_| "https://testnet.zec.rocks:443".to_owned())
}

fn test_seed_hex() -> String {
    test_env("ZAIR_TEST_SEED_HEX")
}

static PIPELINE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn pipeline_lock() -> std::sync::MutexGuard<'static, ()> {
    PIPELINE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("pipeline lock poisoned")
}

fn s(path: &Path) -> &str {
    path.to_str().expect("path is valid UTF-8")
}

fn zair() -> assert_cmd::Command {
    cargo_bin_cmd!("zair")
}

pub fn cached(name: &str) -> PathBuf {
    let dir = PathBuf::from(CACHE);
    fs::create_dir_all(&dir).expect("create cache dir");
    dir.join(name)
}

pub fn config_path(scheme: &str) -> PathBuf {
    cached(&format!("config-{scheme}.json"))
}

pub fn message_path() -> PathBuf {
    cached("claim-message.bin")
}

pub fn vk_path(scheme: &str) -> PathBuf {
    cached(&format!("setup-sapling-vk-{scheme}.params"))
}

pub fn orchard_params_path(scheme: &str) -> PathBuf {
    cached(&format!("setup-orchard-params-{scheme}.bin"))
}

pub fn proofs_path(scheme: &str) -> PathBuf {
    cached(&format!("claim-proofs-{scheme}.json"))
}

pub fn submission_path(scheme: &str) -> PathBuf {
    cached(&format!("claim-submission-{scheme}.json"))
}

fn ensure_seed_and_message() {
    let seed = cached("seed.txt");
    if !seed.exists() {
        let seed_hex = test_seed_hex();
        fs::write(&seed, format!("{seed_hex}\n")).expect("write seed.txt");
    }

    let msg = message_path();
    if !msg.exists() {
        fs::write(&msg, MESSAGE).expect("write claim-message.bin");
    }
}

fn ensure_config() {
    let config = cached("config-native.json");
    let snap_s = cached("snapshot-sapling.bin");
    let snap_o = cached("snapshot-orchard.bin");
    let gap_s = cached("gaptree-sapling.bin");
    let gap_o = cached("gaptree-orchard.bin");

    if config.exists() && snap_s.exists() && snap_o.exists() && gap_s.exists() && gap_o.exists() {
        return;
    }

    let network = test_network();
    let height = test_height();
    let lightwalletd = test_lightwalletd();

    zair()
        .args([
            "config",
            "build",
            "--network",
            &network,
            "--height",
            &height,
            "--lightwalletd",
            &lightwalletd,
            "--pool",
            "both",
            "--scheme-sapling",
            "native",
            "--scheme-orchard",
            "native",
            "--config-out",
            s(&config),
            "--snapshot-out-sapling",
            s(&snap_s),
            "--snapshot-out-orchard",
            s(&snap_o),
            "--gap-tree-out-sapling",
            s(&gap_s),
            "--gap-tree-out-orchard",
            s(&gap_o),
        ])
        .assert()
        .success();
}

fn ensure_config_derived(scheme: &str, target_scheme: ValueCommitmentScheme) {
    let derived_config = cached(&format!("config-{scheme}.json"));
    if derived_config.exists() {
        return;
    }

    let native_config = cached("config-native.json");
    assert!(
        native_config.exists(),
        "config-native.json must exist first - run ensure_config()"
    );

    let text = fs::read_to_string(&native_config).expect("read config-native.json");
    let mut config: AirdropConfiguration =
        serde_json::from_str(&text).expect("parse config-native.json");

    if let Some(sapling) = config.sapling.as_mut() {
        sapling.value_commitment_scheme = target_scheme;
    }
    if let Some(orchard) = config.orchard.as_mut() {
        orchard.value_commitment_scheme = target_scheme;
    }

    let output = serde_json::to_string_pretty(&config).expect("serialize derived config");
    fs::write(&derived_config, output).expect("write derived config");
}

fn ensure_setup_sapling(scheme: &str) {
    let pk = cached(&format!("setup-sapling-pk-{scheme}.params"));
    let vk = vk_path(scheme);

    if pk.exists() && vk.exists() {
        return;
    }

    zair()
        .args([
            "setup",
            "sapling",
            "--scheme",
            scheme,
            "--pk-out",
            s(&pk),
            "--vk-out",
            s(&vk),
        ])
        .assert()
        .success();
}

fn ensure_setup_orchard(scheme: &str) {
    let params = orchard_params_path(scheme);

    if params.exists() {
        return;
    }

    zair()
        .args([
            "setup",
            "orchard",
            "--scheme",
            scheme,
            "--params-out",
            s(&params),
        ])
        .assert()
        .success();
}

pub fn ensure_claim_run(scheme: &str) {
    let _lock = pipeline_lock();

    ensure_seed_and_message();
    ensure_config();
    match scheme {
        "native" => {}
        "sha256" => ensure_config_derived(scheme, ValueCommitmentScheme::Sha256),
        "plain" => ensure_config_derived(scheme, ValueCommitmentScheme::Plain),
        other => panic!("unknown scheme: {other}"),
    }
    ensure_setup_sapling(scheme);
    ensure_setup_orchard(scheme);

    let config = config_path(scheme);
    let seed = cached("seed.txt");
    let message = message_path();
    let snap_s = cached("snapshot-sapling.bin");
    let snap_o = cached("snapshot-orchard.bin");
    let gap_s = cached("gaptree-sapling.bin");
    let gap_o = cached("gaptree-orchard.bin");
    let pk = cached(&format!("setup-sapling-pk-{scheme}.params"));
    let orchard_params = orchard_params_path(scheme);
    let claims_out = cached(&format!("claim-prepared-{scheme}.json"));
    let proofs_out = proofs_path(scheme);
    let secrets_out = cached(&format!("claim-proofs-secrets-{scheme}.json"));
    let submission_out = submission_path(scheme);

    if claims_out.exists() && proofs_out.exists() && secrets_out.exists() && submission_out.exists()
    {
        return;
    }

    let birthday = test_birthday();
    let lightwalletd = test_lightwalletd();

    zair()
        .args([
            "claim",
            "run",
            "--config",
            s(&config),
            "--seed",
            s(&seed),
            "--birthday",
            &birthday,
            "--lightwalletd",
            &lightwalletd,
            "--message",
            s(&message),
            "--snapshot-sapling",
            s(&snap_s),
            "--snapshot-orchard",
            s(&snap_o),
            "--gap-tree-sapling",
            s(&gap_s),
            "--gap-tree-orchard",
            s(&gap_o),
            "--sapling-pk",
            s(&pk),
            "--orchard-params",
            s(&orchard_params),
            "--claims-out",
            s(&claims_out),
            "--proofs-out",
            s(&proofs_out),
            "--secrets-out",
            s(&secrets_out),
            "--submission-out",
            s(&submission_out),
        ])
        .assert()
        .success();
}

#[allow(
    clippy::too_many_lines,
    reason = "End-to-end test helper validates full pipeline output"
)]
pub fn run_pipeline(scheme: &str) {
    ensure_claim_run(scheme);

    let config = config_path(scheme);
    let vk = vk_path(scheme);
    let orchard_params = orchard_params_path(scheme);
    let message = message_path();
    let proofs_out = proofs_path(scheme);
    let submission_out = submission_path(scheme);
    let claims_out = cached(&format!("claim-prepared-{scheme}.json"));
    let secrets_out = cached(&format!("claim-proofs-secrets-{scheme}.json"));

    zair()
        .args([
            "verify",
            "run",
            "--config",
            s(&config),
            "--sapling-vk",
            s(&vk),
            "--orchard-params",
            s(&orchard_params),
            "--submission-in",
            s(&submission_out),
            "--message",
            s(&message),
        ])
        .assert()
        .success();

    assert!(claims_out.exists(), "claim-prepared should exist");
    assert!(proofs_out.exists(), "claim-proofs should exist");
    assert!(secrets_out.exists(), "claim-proofs-secrets should exist");
    assert!(submission_out.exists(), "claim-submission should exist");

    let proofs = load_json(&proofs_out);
    let sapling_proofs = proofs["sapling_proofs"]
        .as_array()
        .expect("sapling_proofs should be an array");
    let orchard_proofs = proofs["orchard_proofs"]
        .as_array()
        .expect("orchard_proofs should be an array");
    assert!(
        !sapling_proofs.is_empty(),
        "should have at least one Sapling proof"
    );
    assert!(
        !orchard_proofs.is_empty(),
        "should have at least one Orchard proof"
    );

    for proof in sapling_proofs {
        match scheme {
            "native" => {
                assert!(
                    proof.get("cv").is_some_and(|v| !v.is_null()),
                    "native scheme: Sapling proof should have cv"
                );
                assert!(
                    proof.get("cv_sha256").is_none_or(Value::is_null),
                    "native scheme: Sapling proof should not have cv_sha256"
                );
            }
            "sha256" => {
                assert!(
                    proof.get("cv_sha256").is_some_and(|v| !v.is_null()),
                    "sha256 scheme: Sapling proof should have cv_sha256"
                );
                assert!(
                    proof.get("cv").is_none_or(Value::is_null),
                    "sha256 scheme: Sapling proof should not have cv"
                );
            }
            "plain" => {
                assert!(
                    proof.get("value").is_some_and(Value::is_u64),
                    "plain scheme: Sapling proof should have value"
                );
                assert!(
                    proof.get("cv").is_none_or(Value::is_null),
                    "plain scheme: Sapling proof should not have cv"
                );
                assert!(
                    proof.get("cv_sha256").is_none_or(Value::is_null),
                    "plain scheme: Sapling proof should not have cv_sha256"
                );
            }
            other => panic!("unknown scheme: {other}"),
        }
    }

    for proof in orchard_proofs {
        match scheme {
            "native" => {
                assert!(
                    proof.get("cv").is_some_and(|v| !v.is_null()),
                    "native scheme: Orchard proof should have cv"
                );
            }
            "sha256" => {
                assert!(
                    proof.get("cv_sha256").is_some_and(|v| !v.is_null()),
                    "sha256 scheme: Orchard proof should have cv_sha256"
                );
            }
            "plain" => {
                assert!(
                    proof.get("value").is_some_and(Value::is_u64),
                    "plain scheme: Orchard proof should have value"
                );
                assert!(
                    proof.get("cv").is_none_or(Value::is_null),
                    "plain scheme: Orchard proof should not have cv"
                );
                assert!(
                    proof.get("cv_sha256").is_none_or(Value::is_null),
                    "plain scheme: Orchard proof should not have cv_sha256"
                );
            }
            other => panic!("unknown scheme: {other}"),
        }
    }

    let submission = load_json(&submission_out);
    let sapling_subs = submission["sapling"]
        .as_array()
        .expect("sapling submissions should be an array");
    let orchard_subs = submission["orchard"]
        .as_array()
        .expect("orchard submissions should be an array");
    assert!(
        !sapling_subs.is_empty(),
        "should have at least one Sapling signed claim"
    );
    assert!(
        !orchard_subs.is_empty(),
        "should have at least one Orchard signed claim"
    );

    for claim in sapling_subs.iter().chain(orchard_subs.iter()) {
        assert!(
            claim.get("spend_auth_sig").is_some_and(Value::is_string),
            "signed claim should have spend_auth_sig"
        );
        assert!(
            claim.get("airdrop_nullifier").is_some_and(Value::is_string),
            "signed claim should have airdrop_nullifier"
        );
    }
}

pub fn load_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("read json")).expect("parse json")
}

pub fn write_tampered(name: &str, value: &Value) -> PathBuf {
    let path = cached(name);
    let body = serde_json::to_string_pretty(value).expect("serialize tampered json");
    fs::write(&path, body).expect("write tampered json");
    path
}

pub fn flip_hex_byte(value: &mut Value, byte_index: usize) {
    let hex_str = value
        .as_str()
        .expect("expected JSON hex field as string")
        .to_owned();
    let mut bytes = hex::decode(&hex_str).expect("expected valid hex string");
    assert!(
        byte_index < bytes.len(),
        "byte_index {byte_index} out of range for {}-byte hex string",
        bytes.len()
    );
    bytes[byte_index] ^= 0xff;
    *value = Value::String(hex::encode(bytes));
}

pub fn verify_proof_failure_stderr(scheme: &str, proofs_in: &Path) -> String {
    let config = config_path(scheme);
    let vk = vk_path(scheme);
    let orchard_params = orchard_params_path(scheme);

    let assert = zair()
        .args([
            "verify",
            "proof",
            "--config",
            s(&config),
            "--sapling-vk",
            s(&vk),
            "--orchard-params",
            s(&orchard_params),
            "--proofs-in",
            s(proofs_in),
        ])
        .assert()
        .failure();

    let output = assert.get_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn verify_signature_failure_stderr(
    scheme: &str,
    submission_in: &Path,
    message_in: &Path,
) -> String {
    let config = config_path(scheme);

    let assert = zair()
        .args([
            "verify",
            "signature",
            "--config",
            s(&config),
            "--submission-in",
            s(submission_in),
            "--message",
            s(message_in),
        ])
        .assert()
        .failure();

    let output = assert.get_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
