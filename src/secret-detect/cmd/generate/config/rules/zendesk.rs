use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn zendesk_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.".to_string(),
        rule_id: "zendesk-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["zendesk"], &alpha_numeric("40"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["zendesk".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("zendesk", &secrets::new_secret(&alpha_numeric("40"))), 
    ];

    validate(rule, &test_positives, None)
}