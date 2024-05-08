use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn doppler() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.".to_string(),
        rule_id: "doppler-api-token".to_string(),
        regex: Regex::new(r"(dp\.pt\.)(?i)[a-z0-9]{43}").unwrap(),
        tags: vec![],
        keywords: vec!["doppler".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("doppler", &format!("dp.pt.{}", secrets::new_secret(&alpha_numeric("43")))),
    ];

    validate(rule, &test_positives, None)
}