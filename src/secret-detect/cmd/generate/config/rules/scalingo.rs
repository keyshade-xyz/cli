use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric_extended_short(length: &str) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn scalingo_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.".to_string(),
        rule_id: "scalingo-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"tk-us-[a-zA-Z0-9-_]{48}", false)).unwrap(),
        tags: vec![],
        keywords: vec!["tk-us-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("scalingo", &format!("tk-us-{}", secrets::new_secret(&alpha_numeric_extended_short("48")))), 
        r#"scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-""#, // gitleaks:allow
    ];

    validate(rule, &test_positives, None)
}