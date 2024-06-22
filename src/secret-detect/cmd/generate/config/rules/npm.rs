use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn npm() -> Rule{
    // Define rule
    let rule = Rule {
        description: "Uncovered an npm access token, potentially compromising package management and code repository access.".to_string(),
        rule_id: "npm-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"npm_[a-z0-9]{36}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["npm_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("npmAccessToken", &format!("npm_{}", secrets::new_secret(&alpha_numeric("36")))), 
    ];

    validate(rule, &test_positives, None)
}