use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn airtable() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.".to_string(),
        rule_id: "airtable-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["airtable"], &alpha_numeric("17"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["airtable".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("airtable", &secrets::new_secret(&alpha_numeric("17"))),
    ];

    validate(rule, &test_positives, None)
}