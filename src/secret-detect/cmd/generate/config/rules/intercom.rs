use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn intercom() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.".to_string(),
        rule_id: "intercom-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["intercom"], &alpha_numeric_extended("60"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["intercom".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("intercom", &secrets::new_secret(&alpha_numeric_extended("60"))), 
    ];

    validate(rule, &test_positives, None)
}