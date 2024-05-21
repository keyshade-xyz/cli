use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - hex8_4_4_4_12() -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn kucoin_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.".to_string(),
        rule_id: "kucoin-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["kucoin"], &hex("24"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["kucoin".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("kucoin", &secrets::new_secret(&hex("24"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn kucoin_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.".to_string(),
        rule_id: "kucoin-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["kucoin"], &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords: vec!["kucoin".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("kucoin", &secrets::new_secret(&hex8_4_4_4_12())), 
    ];

    validate(rule, &test_positives, None)
}