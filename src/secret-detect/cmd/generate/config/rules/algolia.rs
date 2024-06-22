use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn algolia_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.".to_string(),
        rule_id: "algolia-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["algolia"], r"[a-z0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["algolia".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("algolia_key := {}", secrets::new_secret(&hex("32"))),
    ];

    validate(rule, &test_positives, None)
}