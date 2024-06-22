use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn travis_ci_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.".to_string(),
        rule_id: "travisci-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["travis"], &alpha_numeric("22"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["travis".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("travis", &secrets::new_secret(&alpha_numeric("22"))),
    ];

    validate(rule, &test_positives, None)
}