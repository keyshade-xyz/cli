use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn contentful() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.".to_string(),
        rule_id: "contentful-delivery-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["contentful"], &alpha_numeric_extended("43"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["contentful".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("contentful", &secrets::new_secret(&alpha_numeric("43"))), 
    ];

    validate(rule, &test_positives, None)
}