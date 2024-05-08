use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn datadogtoken_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.".to_string(),
        rule_id: "datadog-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["datadog"], &alpha_numeric("40"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["datadog".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("datadog", &secrets::new_secret(&alpha_numeric("40"))), 
    ];

    validate(rule, &test_positives, None)
}