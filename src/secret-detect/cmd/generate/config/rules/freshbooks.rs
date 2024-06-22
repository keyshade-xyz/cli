use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn freshbooks_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.".to_string(),
        rule_id: "freshbooks-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["freshbooks"], &alpha_numeric("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["freshbooks".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("freshbooks", &secrets::new_secret(&alpha_numeric("64"))), 
    ];

    validate(rule, &test_positives, None)
}