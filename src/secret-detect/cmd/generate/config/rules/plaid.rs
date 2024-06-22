use regex::Regex;
use std::fmt;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - hex8_4_4_4_12() -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn plaid_access_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.".to_string(),
        rule_id: "plaid-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["plaid"], &alpha_numeric("24"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["plaid".to_string()],
        allowlist: Allowlist::default(),
        entropy: Some(3.5),
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("plaid", &secrets::new_secret(&alpha_numeric("24"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn plaid_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.".to_string(),
        rule_id: "plaid-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["plaid"], &alpha_numeric("30"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["plaid".to_string()],
        allowlist: Allowlist::default(),
        entropy: Some(3.5),
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("plaid", &secrets::new_secret(&alpha_numeric("30"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn plaid_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.".to_string(),
        rule_id: "plaid-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["plaid"], &format!("access-(?:sandbox|development|production)-{}", hex8_4_4_4_12()), true)).unwrap(),
        tags: vec![],
        keywords: vec!["plaid".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("plaid", &secrets::new_secret(&format!("access-(?:sandbox|development|production)-{}", hex8_4_4_4_12()))),
    ];

    validate(rule, &test_positives, None)
}