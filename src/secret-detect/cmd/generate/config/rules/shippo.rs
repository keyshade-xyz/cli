use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn shippo_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.".to_string(),
        rule_id: "shippo-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"shippo_(live|test)_[a-f0-9]{40}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["shippo_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("shippo", &format!("shippo_live_{}", secrets::new_secret(&hex("40")))),
        generate_sample_secret("shippo", &format!("shippo_test_{}", secrets::new_secret(&hex("40")))),
    ];

    validate(rule, &test_positives, None)
}