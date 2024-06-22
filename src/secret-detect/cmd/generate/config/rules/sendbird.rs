use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - hex8_4_4_4_12() -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sendbird_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.".to_string(),
        rule_id: "sendbird-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["sendbird"], &hex("40"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["sendbird".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("sendbird", &secrets::new_secret(&hex("40"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn sendbird_access_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.".to_string(),
        rule_id: "sendbird-access-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["sendbird"], &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords: vec!["sendbird".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("sendbird", &secrets::new_secret(&hex8_4_4_4_12())),
    ];

    validate(rule, &test_positives, None)
}