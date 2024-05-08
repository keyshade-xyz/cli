use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn fastly_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.".to_string(),
        rule_id: "fastly-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["fastly"], &alpha_numeric_extended("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["fastly".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("fastly", &secrets::new_secret(&alpha_numeric_extended("32"))), 
    ];

    validate(rule, &test_positives, None)
}