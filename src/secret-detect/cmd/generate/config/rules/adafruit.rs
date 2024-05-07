use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn adafruit_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.".to_string(),
        rule_id: "adafruit-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["adafruit"], &alpha_numeric_extended_short("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["adafruit".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("adafruit", &secrets::new_secret(&alpha_numeric_extended_short("32"))), 
    ];

    validate(rule, &test_positives, None)
}