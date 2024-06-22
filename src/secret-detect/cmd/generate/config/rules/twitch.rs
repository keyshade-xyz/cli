use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn twitch_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.".to_string(),
        rule_id: "twitch-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitch"], &alpha_numeric("30"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitch".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitch", &secrets::new_secret(&alpha_numeric("30"))), 
    ];

    validate(rule, &test_positives, None)
}