use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn finicity_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.".to_string(),
        rule_id: "finicity-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["finicity"], &alpha_numeric("20"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["finicity".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("finicity", &secrets::new_secret(&alpha_numeric("20"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn finicity_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.".to_string(),
        rule_id: "finicity-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["finicity"], &hex("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["finicity".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("finicity", &secrets::new_secret(&hex("32"))),
    ];

    validate(rule, &test_positives, None)
}