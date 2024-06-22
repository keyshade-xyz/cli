use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn twitter_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.".to_string(),
        rule_id: "twitter-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitter"], &alpha_numeric("25"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitter", &secrets::new_secret(&alpha_numeric("25"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn twitter_api_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.".to_string(),
        rule_id: "twitter-api-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitter"], &alpha_numeric("50"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitter", &secrets::new_secret(&alpha_numeric("50"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn twitter_bearer_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.".to_string(),
        rule_id: "twitter-bearer-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitter"], r"A{22}[a-zA-Z0-9%]{80,100}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitter", &secrets::new_secret(r"A{22}[a-zA-Z0-9%]{80,100}")),
    ];

    validate(rule, &test_positives, None)
}

pub fn twitter_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.".to_string(),
        rule_id: "twitter-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitter"], r"[0-9]{15,25}-[a-zA-Z0-9]{20,40}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitter", &secrets::new_secret(r"[0-9]{15,25}-[a-zA-Z0-9]{20,40}")),
    ];

    validate(rule, &test_positives, None)
}

pub fn twitter_access_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.".to_string(),
        rule_id: "twitter-access-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["twitter"], &alpha_numeric("45"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["twitter".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("twitter", &secrets::new_secret(&alpha_numeric("45"))), 
    ];

    validate(rule, &test_positives, None)
}