use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn databricks() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.".to_string(),
        rule_id: "databricks-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"dapi[a-h0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dapi".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("databricks", &format!("dapi{}", secrets::new_secret(&hex("32")))),
    ];

    validate(rule, &test_positives, None)
}