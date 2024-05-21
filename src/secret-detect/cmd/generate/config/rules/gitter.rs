use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn gitter_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.".to_string(),
        rule_id: "gitter-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["gitter"], &alpha_numeric_extended_short("40"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["gitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gitter", &secrets::new_secret(&alpha_numeric_extended_short("40"))), 
    ];

    validate(rule, &test_positives, None)
}