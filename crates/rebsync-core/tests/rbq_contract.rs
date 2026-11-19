//! Keeps the client's constants and validators equal to the shared wire
//! contract. Dash runs the same vectors against its server validators.
use rebsync_core::rbq_contract::*;
use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!("../../../contracts/rbq-repository.v1.json"))
        .expect("contract is valid JSON")
}

fn strings<'a>(value: &'a Value, path: &str) -> Vec<&'a str> {
    value
        .pointer(path)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{path} is an array"))
        .iter()
        .map(|item| item.as_str().expect("vector entries are strings"))
        .collect()
}

fn number(value: &Value, path: &str) -> usize {
    value
        .pointer(path)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{path}")) as usize
}

#[test]
fn constants_match_the_contract() {
    let c = contract();
    assert_eq!(c["contract"], SCHEMA);
    assert_eq!(c["responses"]["describe"]["schema"], SCHEMA);
    assert_eq!(c["endpoint"]["path_prefix"], ENDPOINT_PATH_PREFIX);
    assert_eq!(c["headers"]["content_sha256"], CONTENT_SHA256_HEADER);
    assert_eq!(number(&c, "/limits/object_bytes"), MAX_OBJECT_BYTES);
    assert_eq!(number(&c, "/limits/key_bytes"), MAX_KEY_BYTES);
    assert_eq!(number(&c, "/limits/segment_bytes"), MAX_SEGMENT_BYTES);
    assert_eq!(number(&c, "/limits/list_limit_min"), 1);
    assert_eq!(number(&c, "/limits/list_limit_max"), LIST_LIMIT_MAX);
    assert_eq!(number(&c, "/limits/list_limit_default"), LIST_LIMIT_DEFAULT);
}

#[test]
fn key_vectors() {
    let c = contract();
    for key in strings(&c, "/vectors/keys/valid") {
        assert!(
            ObjectKey::parse(key).is_ok(),
            "key should be valid: {key:?}"
        );
    }
    for key in strings(&c, "/vectors/keys/invalid") {
        assert!(
            ObjectKey::parse(key).is_err(),
            "key should be invalid: {key:?}"
        );
    }
    let segment = "a".repeat(MAX_SEGMENT_BYTES);
    assert!(ObjectKey::parse(&segment).is_ok());
    assert!(ObjectKey::parse(&format!("{segment}a")).is_err());
}

#[test]
fn prefix_vectors() {
    let c = contract();
    for prefix in strings(&c, "/vectors/prefixes/valid") {
        assert!(
            validate_prefix(prefix).is_ok(),
            "prefix should be valid: {prefix:?}"
        );
    }
    for prefix in strings(&c, "/vectors/prefixes/invalid") {
        assert!(
            validate_prefix(prefix).is_err(),
            "prefix should be invalid: {prefix:?}"
        );
    }
}

#[test]
fn token_and_endpoint_vectors() {
    let c = contract();
    for token in strings(&c, "/vectors/tokens/valid") {
        assert!(valid_token(token), "token should be valid: {token:?}");
    }
    for token in strings(&c, "/vectors/tokens/invalid") {
        assert!(!valid_token(token), "token should be invalid: {token:?}");
    }
    for id in strings(&c, "/vectors/endpoint_ids/valid") {
        assert!(valid_endpoint_id(id), "endpoint id should be valid: {id:?}");
    }
    for id in strings(&c, "/vectors/endpoint_ids/invalid") {
        assert!(
            !valid_endpoint_id(id),
            "endpoint id should be invalid: {id:?}"
        );
    }
}
