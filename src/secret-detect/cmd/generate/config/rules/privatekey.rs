use regex::Regex;

use crate::config::{Allowlist, Rule};

// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn private_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.".to_string(),
        rule_id: "private-key".to_string(),
        regex: Regex::new(r"(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY( BLOCK)?-----").unwrap(),
        tags: vec![],
        keywords: vec!["-----BEGIN".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----"#,
        r#"-----BEGIN RSA PRIVATE KEY-----
abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----
"#,
        r#"-----BEGIN PRIVATE KEY BLOCK-----
anything
-----END PRIVATE KEY BLOCK-----"#,
    ];

    validate(rule, &test_positives, None)
}