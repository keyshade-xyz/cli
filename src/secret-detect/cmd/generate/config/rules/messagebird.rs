use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - hex8_4_4_4_12() -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn messagebird_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.".to_string(),
        rule_id: "messagebird-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["messagebird", "message-bird", "message_bird"], &alpha_numeric("25"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["messagebird".to_string(), "message-bird".to_string(), "message_bird".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("messagebird", &secrets::new_secret(&alpha_numeric("25"))),
        generate_sample_secret("message-bird", &secrets::new_secret(&alpha_numeric("25"))),
        generate_sample_secret("message_bird", &secrets::new_secret(&alpha_numeric("25"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn messagebird_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.".to_string(),
        rule_id: "messagebird-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["messagebird", "message-bird", "message_bird"], &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords: vec!["messagebird".to_string(), "message-bird".to_string(), "message_bird".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"const MessageBirdClientID = "12345678-ABCD-ABCD-ABCD-1234567890AB""#,
    ];

    validate(rule, &test_positives, None)
}