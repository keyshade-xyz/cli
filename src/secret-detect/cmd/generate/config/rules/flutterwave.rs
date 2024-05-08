use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn flutterwave_public_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.".to_string(),
        rule_id: "flutterwave-public-key".to_string(),
        regex: Regex::new(r"FLWPUBK_TEST-(?i)[a-h0-9]{32}-X").unwrap(),
        tags: vec![],
        keywords: vec!["FLWPUBK_TEST".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("flutterwavePubKey", &format!("FLWPUBK_TEST-{}-X", secrets::new_secret(&hex("32")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn flutterwave_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.".to_string(),
        rule_id: "flutterwave-secret-key".to_string(),
        regex: Regex::new(r"FLWSECK_TEST-(?i)[a-h0-9]{32}-X").unwrap(),
        tags: vec![],
        keywords: vec!["FLWSECK_TEST".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("flutterwavePubKey", &format!("FLWSECK_TEST-{}-X", secrets::new_secret(&hex("32")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn flutterwave_enc_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.".to_string(),
        rule_id: "flutterwave-encryption-key".to_string(),
        regex: Regex::new(r"FLWSECK_TEST-(?i)[a-h0-9]{12}").unwrap(),
        tags: vec![],
        keywords: vec!["FLWSECK_TEST".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("flutterwavePubKey", &format!("FLWSECK_TEST-{}", secrets::new_secret(&hex("12")))), 
    ];

    validate(rule, &test_positives, None)
}