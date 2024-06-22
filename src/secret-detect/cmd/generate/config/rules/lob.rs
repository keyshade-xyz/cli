use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn lob_pub_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.".to_string(),
        rule_id: "lob-pub-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["lob"], r"(test|live)_pub_[a-f0-9]{31}", true)).unwrap(),
        tags: vec![],
        keywords: vec![
            "test_pub".to_string(), 
            "live_pub".to_string(), 
            "_pub".to_string(),
        ],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("lob", &format!("test_pub_{}", secrets::new_secret(&hex("31")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn lob_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.".to_string(),
        rule_id: "lob-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["lob"], r"(live|test)_[a-f0-9]{35}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["test_".to_string(), "live_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("lob", &format!("test_{}", secrets::new_secret(&hex("35")))), 
    ];

    validate(rule, &test_positives, None)
}