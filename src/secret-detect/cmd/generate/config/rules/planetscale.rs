use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn planetscale_password() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.".to_string(),
        rule_id: "planetscale-password".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"pscale_pw_(?i)[a-z0-9=\-_\.]{32,64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["pscale_pw_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("planetScalePassword", &format!("pscale_pw_{}", secrets::new_secret(&alpha_numeric_extended("32")))),
        generate_sample_secret("planetScalePassword", &format!("pscale_pw_{}", secrets::new_secret(&alpha_numeric_extended("43")))),
        generate_sample_secret("planetScalePassword", &format!("pscale_pw_{}", secrets::new_secret(&alpha_numeric_extended("64")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn planetscale_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a PlanetScale API token, potentially compromising database management and operations.".to_string(),
        rule_id: "planetscale-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["pscale_tkn_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("planetScalePassword", &format!("pscale_tkn_{}", secrets::new_secret(&alpha_numeric_extended("32")))), 
        generate_sample_secret("planetScalePassword", &format!("pscale_tkn_{}", secrets::new_secret(&alpha_numeric_extended("43")))), 
        generate_sample_secret("planetScalePassword", &format!("pscale_tkn_{}", secrets::new_secret(&alpha_numeric_extended("64")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn planetscale_oauth_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.".to_string(),
        rule_id: "planetscale-oauth-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["pscale_oauth_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("planetScalePassword", &format!("pscale_oauth_{}", secrets::new_secret(&alpha_numeric_extended("32")))), 
        generate_sample_secret("planetScalePassword", &format!("pscale_oauth_{}", secrets::new_secret(&alpha_numeric_extended("43")))), 
        generate_sample_secret("planetScalePassword", &format!("pscale_oauth_{}", secrets::new_secret(&alpha_numeric_extended("64")))), 
    ];

    validate(rule, &test_positives, None)
}