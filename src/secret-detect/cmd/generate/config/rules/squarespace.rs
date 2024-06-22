use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex8_4_4_4_12() -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn squarespace_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.".to_string(),
        rule_id: "squarespace-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["squarespace"], &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords: vec!["squarespace".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("squarespace", &secrets::new_secret(&hex8_4_4_4_12())),
    ];

    validate(rule, &test_positives, None)
}