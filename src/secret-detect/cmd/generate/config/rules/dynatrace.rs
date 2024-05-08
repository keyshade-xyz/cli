use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn dynatrace() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.".to_string(),
        rule_id: "dynatrace-api-token".to_string(),
        regex: Regex::new(r"dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}").unwrap(),
        tags: vec![],
        keywords: vec!["dynatrace".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("dynatrace", &format!("dt0c01.{}.{}", secrets::new_secret(&alpha_numeric("24")), secrets::new_secret(&alpha_numeric("64")))),
    ];

    validate(rule, &test_positives, None)
}