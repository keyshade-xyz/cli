use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn digitalocean_pat() -> Rule {
    let rule = Rule {
        description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.".to_string(),
        rule_id: "digitalocean-pat".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"dop_v1_[a-f0-9]{64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dop_v1_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        generate_sample_secret("do", &format!("dop_v1_{}", secrets::new_secret(&hex("64")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn digitalocean_oauth_token() -> Rule {
    let rule = Rule {
        description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.".to_string(),
        rule_id: "digitalocean-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"doo_v1_[a-f0-9]{64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["doo_v1_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        generate_sample_secret("do", &format!("doo_v1_{}", secrets::new_secret(&hex("64")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn digitalocean_refresh_token() -> Rule {
    let rule = Rule {
        description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.".to_string(),
        rule_id: "digitalocean-refresh-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"dor_v1_[a-f0-9]{64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["dor_v1_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        generate_sample_secret("do", &format!("dor_v1_{}", secrets::new_secret(&hex("64")))), 
    ];

    validate(rule, &test_positives, None)
}