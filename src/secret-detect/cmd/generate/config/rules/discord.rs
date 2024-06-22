use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - numeric(length: &str) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn discord_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.".to_string(),
        rule_id: "discord-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["discord"], &hex("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["discord".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("discord", &secrets::new_secret(&hex("64"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn discord_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.".to_string(),
        rule_id: "discord-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["discord"], &numeric("18"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["discord".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("discord", &secrets::new_secret(&numeric("18"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn discord_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.".to_string(),
        rule_id: "discord-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["discord"], &alpha_numeric_extended("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["discord".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("discord", &secrets::new_secret(&numeric("32"))),
    ];

    validate(rule, &test_positives, None)
}