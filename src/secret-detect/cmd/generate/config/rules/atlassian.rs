use regex::Regex;

use crate::config::{Allowlist, Rule};


// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn atlassian() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.".to_string(),
        rule_id: "atlassian-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["atlassian", "confluence", "jira"], &alpha_numeric("24"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["atlassian".to_string(), "confluence".to_string(), "jira".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("atlassian", &secrets::new_secret(&alpha_numeric("24"))), 
        generate_sample_secret("confluence", &secrets::new_secret(&alpha_numeric("24"))),
    ];

    validate(rule, &test_positives, None)
}