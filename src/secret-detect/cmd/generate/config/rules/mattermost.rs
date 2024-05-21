use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn mattermost_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.".to_string(),
        rule_id: "mattermost-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["mattermost"], &alpha_numeric("26"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["mattermost".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mattermost", &secrets::new_secret(&alpha_numeric("26"))), 
    ];

    validate(rule, &test_positives, None)
}