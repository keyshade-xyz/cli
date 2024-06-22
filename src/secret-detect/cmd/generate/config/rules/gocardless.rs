use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn gocardless() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.".to_string(),
        rule_id: "gocardless-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["gocardless"], r"live_(?i)[a-z0-9\-_=]{40}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["live_".to_string(), "gocardless".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gocardless", &format!("live_{}", secrets::new_secret(&alpha_numeric_extended("40")))),
    ];

    validate(rule, &test_positives, None)
}