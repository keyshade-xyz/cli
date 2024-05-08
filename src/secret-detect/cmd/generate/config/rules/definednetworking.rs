use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn defined_networking_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.".to_string(),
        rule_id: "defined-networking-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["dnkey"], r"dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dnkey".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("dnkey", &format!("dnkey-{}-{}", secrets::new_secret(&alpha_numeric_extended("26")), secrets::new_secret(&alpha_numeric_extended("52")))),
    ];

    validate(rule, &test_positives, None)
}