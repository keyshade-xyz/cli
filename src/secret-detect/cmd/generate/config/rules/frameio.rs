use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn frame_io() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Frame.io API token, potentially compromising video collaboration and project management.".to_string(),
        rule_id: "frameio-api-token".to_string(),
        regex: Regex::new(r"fio-u-(?i)[a-z0-9\-_=]{64}").unwrap(),
        tags: vec![],
        keywords: vec!["fio-u-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("frameio", &format!("fio-u-{}", secrets::new_secret(&alpha_numeric_extended("64")))), 
    ];

    validate(rule, &test_positives, None)
}