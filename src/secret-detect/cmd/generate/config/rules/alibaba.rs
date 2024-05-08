use regex::Regex;

use crate::config::{Allowlist, Rule};


// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn alibaba_access_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.".to_string(),
        rule_id: "alibaba-access-key-id".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"(LTAI)(?i)[a-z0-9]{20}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["LTAI".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("alibabaKey := \"LTAI{}
\"", secrets::new_secret(&hex("20"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn alibaba_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.".to_string(),
        rule_id: "alibaba-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["alibaba"], &alpha_numeric("30"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["alibaba".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("alibaba", &secrets::new_secret(&alpha_numeric("30"))), 
    ];

    validate(rule, &test_positives, None)
}