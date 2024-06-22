use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn okta_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.".to_string(),
        rule_id: "okta-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["okta"], &alpha_numeric_extended("42"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["okta".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("okta", &secrets::new_secret(&alpha_numeric("42"))), 
    ];

    validate(rule, &test_positives, None)
}