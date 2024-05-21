use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sentry_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Sentry Access Token, risking unauthorized access to error tracking services and sensitive application data.".to_string(),
        rule_id: "sentry-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["sentry"], &hex("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["sentry".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("sentry", &secrets::new_secret(&hex("64"))), 
    ];

    validate(rule, &test_positives, None)
}