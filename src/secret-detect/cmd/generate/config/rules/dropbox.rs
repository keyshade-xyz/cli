use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn drop_box_api_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.".to_string(),
        rule_id: "dropbox-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["dropbox"], &alpha_numeric("15"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["dropbox".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("dropbox", &secrets::new_secret(&alpha_numeric("15"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn drop_box_short_lived_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.".to_string(),
        rule_id: "dropbox-short-lived-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["dropbox"], r"sl\.[a-z0-9\-=_]{135}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dropbox".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // TODO: Implement validation for short-lived token
    rule
}

pub fn drop_box_long_lived_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.".to_string(),
        rule_id: "dropbox-long-lived-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["dropbox"], r"[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dropbox".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // TODO: Implement validation for long-lived token
    rule 
}