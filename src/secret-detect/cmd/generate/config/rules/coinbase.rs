use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn coinbase_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.".to_string(),
        rule_id: "coinbase-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["coinbase"], &alpha_numeric_extended_short("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["coinbase".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("coinbase", &secrets::new_secret(&alpha_numeric_extended_short("64"))), 
    ];

    validate(rule, &test_positives, None)
}