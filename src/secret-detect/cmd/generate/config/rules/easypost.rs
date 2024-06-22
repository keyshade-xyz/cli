use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn easy_post() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.".to_string(),
        rule_id: "easypost-api-token".to_string(),
        regex: Regex::new(r"\bEZAK(?i)[a-z0-9]{54}").unwrap(),
        tags: vec![],
        keywords: vec!["EZAK".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("EZAK", &format!("EZAK{}", secrets::new_secret(&alpha_numeric("54")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn easy_post_test_api() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.".to_string(),
        rule_id: "easypost-test-api-token".to_string(),
        regex: Regex::new(r"\bEZTK(?i)[a-z0-9]{54}").unwrap(),
        tags: vec![],
        keywords: vec!["EZTK".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("EZTK", &format!("EZTK{}", secrets::new_secret(&alpha_numeric("54")))),
    ];

    validate(rule, &test_positives, None)
}