use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn vault_service_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.".to_string(),
        rule_id: "vault-service-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"hvs\.[a-z0-9_-]{90,100}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["hvs".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("vault", &format!("hvs.{}", secrets::new_secret(&alpha_numeric_extended_short("90")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn vault_batch_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.".to_string(),
        rule_id: "vault-batch-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"hvb\.[a-z0-9_-]{138,212}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["hvb".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("vault", &format!("hvb.{}", secrets::new_secret(&alpha_numeric_extended_short("138")))),
    ];

    validate(rule, &test_positives, None)
}