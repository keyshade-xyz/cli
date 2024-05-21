use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - hex(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn linear_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.".to_string(),
        rule_id: "linear-api-key".to_string(),
        regex: Regex::new(r"lin_api_(?i)[a-z0-9]{40}").unwrap(),
        tags: vec![],
        keywords: vec!["lin_api_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("linear", &format!("lin_api_{}", secrets::new_secret(&alpha_numeric("40")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn linear_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.".to_string(),
        rule_id: "linear-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["linear"], &hex("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["linear".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("linear", &secrets::new_secret(&hex("32"))),
    ];

    validate(rule, &test_positives, None)
}