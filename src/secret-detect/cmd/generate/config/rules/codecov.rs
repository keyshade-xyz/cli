use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn codecov_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.".to_string(),
        rule_id: "codecov-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["codecov"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["codecov".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("codecov", &secrets::new_secret(&alpha_numeric("32"))), 
    ];

    validate(rule, &test_positives, None)
}