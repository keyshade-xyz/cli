use regex::Regex;

use crate::config::{Allowlist, Rule};


// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn aws() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.".to_string(),
        rule_id: "aws-access-token".to_string(),
        regex: Regex::new(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}").unwrap(),
        tags: vec![],
        keywords: vec![
            "AKIA".to_string(), 
            "ASIA".to_string(), 
            "ABIA".to_string(), 
            "ACCA".to_string(),
        ],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![generate_sample_secret("AWS", "AKIALALEMEL33243OLIB")]; // gitleaks:allow

    validate(rule, &test_positives, None)
}