//! The shared ed25519-jcs-v1 vectors from ragbaz-common, vendored with a lock.
use rebsync_core::gift;
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../contracts/vendor/gift-signature.v1.vectors.json");
const LOCK: &str = include_str!("../../../contracts/vendor/gift-signature.v1.lock.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn vendored_vectors_match_their_lock() {
    let lock: Value = serde_json::from_str(LOCK).unwrap();
    assert_eq!(lock["repository"], "tabenius/ragbaz-common");
    assert_eq!(lock["path"], "schemas/gift-signature.v1.vectors.json");
    assert_eq!(
        lock["sha256"].as_str().unwrap(),
        format!("{:x}", Sha256::digest(VECTORS.as_bytes()))
    );
    assert_eq!(vectors()["format"], gift::FORMAT);
}

#[test]
fn canonical_json_matches_every_vector() {
    for case in vectors()["canonical"].as_array().unwrap() {
        assert_eq!(
            gift::canonical_json(&case["input"]).unwrap(),
            case["expect"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn values_outside_the_canonical_subset_are_refused() {
    for case in vectors()["rejected_canonical"].as_array().unwrap() {
        let text = case["input_json"].as_str().unwrap();
        // A parser may refuse it already (1e400); otherwise canonicalisation must.
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            assert!(gift::canonical_json(&value).is_err(), "{}", case["name"]);
        }
    }
    let mut deep = Value::from(0);
    for _ in 0..40 {
        deep = Value::Array(vec![deep]);
    }
    assert!(gift::canonical_json(&deep).is_err());
}

#[test]
fn every_signature_vector_verifies_to_its_expected_outcome() {
    for case in vectors()["cases"].as_array().unwrap() {
        let outcome = gift::verify(
            &case["gift"],
            case["now"].as_i64().unwrap(),
            case.get("recipient"),
        );
        let got = outcome.map_or_else(|refusal| refusal.code(), |()| "ok");
        assert_eq!(got, case["expect"].as_str().unwrap(), "{}", case["name"]);
    }
}
