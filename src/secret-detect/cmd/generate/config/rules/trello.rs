use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn trello_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Trello Access Token".to_string(),
        rule_id: "trello-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["trello"], r"[a-zA-Z-0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["trello".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("trello", &secrets::new_secret(r"[a-zA-Z-0-9]{32}")), 
    ];

    validate(rule, &test_positives, None)
}