use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn gcp_service_account() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Google (GCP) Service-account".to_string(),
        rule_id: "gcp-service-account".to_string(),
        regex: Regex::new(r#""type": "service_account""#).unwrap(),
        tags: vec![],
        keywords: vec![r#""type": "service_account""#.to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#""type": "service_account""#, 
    ];

    validate(rule, &test_positives, None)
}

pub fn gcp_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches.".to_string(),
        rule_id: "gcp-api-key".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"AIza[0-9A-Za-z\\-_]{35}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["AIza".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gcp", &secrets::new_secret(r"AIza[0-9A-Za-z\\-_]{35}")), 
    ];

    validate(rule, &test_positives, None)
}