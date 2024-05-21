use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn rapidapi_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.".to_string(),
        rule_id: "rapidapi-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["rapidapi"], &alpha_numeric_extended_short("50"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["rapidapi".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("rapidapi", &secrets::new_secret(&alpha_numeric_extended_short("50"))), 
    ];

    validate(rule, &test_positives, None)
}