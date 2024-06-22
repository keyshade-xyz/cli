use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn droneci_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.".to_string(),
        rule_id: "droneci-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["droneci"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["droneci".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("droneci", &secrets::new_secret(&alpha_numeric("32"))), 
    ];

    validate(rule, &test_positives, None)
}