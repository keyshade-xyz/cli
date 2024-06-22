use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn adobe_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.".to_string(),
        rule_id: "adobe-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["adobe"], &hex("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["adobe".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("adobe", &secrets::new_secret(&hex("32"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn adobe_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.".to_string(),
        rule_id: "adobe-client-secret".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"(p8e-)(?i)[a-z0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["p8e-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("adobeClient := \"p8e-{}
\"", secrets::new_secret(&hex("32"))), 
    ];

    validate(rule, &test_positives, None)
}