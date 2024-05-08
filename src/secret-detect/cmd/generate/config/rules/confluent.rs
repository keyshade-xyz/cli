use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn confluent_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.".to_string(),
        rule_id: "confluent-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["confluent"], &alpha_numeric("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["confluent".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("confluent", &secrets::new_secret(&alpha_numeric("64"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn confluent_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.".to_string(),
        rule_id: "confluent-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["confluent"], &alpha_numeric("16"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["confluent".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("confluent", &secrets::new_secret(&alpha_numeric("16"))), 
    ];

    validate(rule, &test_positives, None)
}