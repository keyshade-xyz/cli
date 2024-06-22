use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - hex(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn new_relic_user_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.".to_string(),
        rule_id: "new-relic-user-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["new-relic", "newrelic", "new_relic"], r"NRAK-[a-z0-9]{27}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["NRAK".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("new-relic", &format!("NRAK-{}", secrets::new_secret(&alpha_numeric("27")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn new_relic_user_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.".to_string(),
        rule_id: "new-relic-user-api-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["new-relic", "newrelic", "new_relic"], &alpha_numeric("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["new-relic".to_string(), "newrelic".to_string(), "new_relic".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("new-relic", &secrets::new_secret(&alpha_numeric("64"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn new_relic_browser_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.".to_string(),
        rule_id: "new-relic-browser-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["new-relic", "newrelic", "new_relic"], r"NRJS-[a-f0-9]{19}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["NRJS-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("new-relic", &format!("NRJS-{}", secrets::new_secret(&hex("19")))),
    ];

    validate(rule, &test_positives, None)
}