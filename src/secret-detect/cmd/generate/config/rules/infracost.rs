use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn infracost_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.".to_string(),
        rule_id: "infracost-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"ico-[a-zA-Z0-9]{32}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["ico-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("ico", &format!("ico-{}", secrets::new_secret(r"[A-Za-z0-9]{32}"))),
    ];

    validate(rule, &test_positives, None)
}