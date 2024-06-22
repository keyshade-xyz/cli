use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn mailgun_private_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.".to_string(),
        rule_id: "mailgun-private-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["mailgun"], r"key-[a-f0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["mailgun".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mailgun", &format!("key-{}", secrets::new_secret(&hex("32")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn mailgun_pub_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.".to_string(),
        rule_id: "mailgun-pub-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["mailgun"], r"pubkey-[a-f0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["mailgun".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mailgun", &format!("pubkey-{}", secrets::new_secret(&hex("32")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn mailgun_signing_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.".to_string(),
        rule_id: "mailgun-signing-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["mailgun"], r"[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["mailgun".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mailgun", &format!("{}-00001111-22223333", secrets::new_secret(&hex("32")))),
    ];

    validate(rule, &test_positives, None)
}