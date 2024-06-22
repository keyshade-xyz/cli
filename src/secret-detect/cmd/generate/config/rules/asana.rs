use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - numeric(length: &str) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn asana_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.".to_string(),
        rule_id: "asana-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["asana"], &numeric("16"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["asana".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("asana", &secrets::new_secret(&numeric("16"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn asana_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.".to_string(),
        rule_id: "asana-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["asana"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["asana".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("asana", &secrets::new_secret(&alpha_numeric("32"))),
    ];

    validate(rule, &test_positives, None)
}