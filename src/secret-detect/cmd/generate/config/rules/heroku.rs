use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex8_4_4_4_12() -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn heroku() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.".to_string(),
        rule_id: "heroku-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["heroku"], &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords: vec!["heroku".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"const HEROKU_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB""#,
        r#"heroku_api_key = "832d2129-a846-4e27-99f4-7004b6ad53ef""#,  
    ];

    validate(rule, &test_positives, None)
}