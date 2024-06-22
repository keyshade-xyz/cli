use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn linkedin_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.".to_string(),
        rule_id: "linkedin-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["linkedin", "linked-in"], &alpha_numeric("16"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["linkedin".to_string(), "linked-in".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("linkedin", &secrets::new_secret(&alpha_numeric("16"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn linkedin_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.".to_string(),
        rule_id: "linkedin-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["linkedin", "linked-in"], &alpha_numeric("14"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["linkedin".to_string(), "linked-in".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("linkedin", &secrets::new_secret(&alpha_numeric("14"))), 
    ];

    validate(rule, &test_positives, None)
}