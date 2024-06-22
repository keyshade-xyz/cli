use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn duffel() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.".to_string(),
        rule_id: "duffel-api-token".to_string(),
        regex: Regex::new(r"duffel_(test|live)_(?i)[a-z0-9_\-=]{43}").unwrap(),
        tags: vec![],
        keywords: vec!["duffel".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("duffel", &format!("duffel_test_{}", secrets::new_secret(&alpha_numeric_extended("43")))),
    ];

    validate(rule, &test_positives, None)
}