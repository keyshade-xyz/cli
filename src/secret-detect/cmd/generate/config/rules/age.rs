use regex::Regex;

use crate::config::{Allowlist, Rule};

// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn age_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.".to_string(),
        rule_id: "age-secret-key".to_string(),
        regex: Regex::new(r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}").unwrap(),
        tags: vec![],
        keywords: vec!["AGE-SECRET-KEY-1".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"apiKey := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"#, // gitleaks:allow
    ];

    validate(rule, &test_positives, None)
}