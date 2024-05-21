use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sendgrid_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.".to_string(),
        rule_id: "sendgrid-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"SG\.(?i)[a-z0-9=_\-\.]{66}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["SG.".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("sengridAPIToken", &format!("SG.{}", secrets::new_secret(&alpha_numeric_extended("66")))), 
    ];

    validate(rule, &test_positives, None)
}