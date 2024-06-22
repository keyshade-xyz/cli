use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn readme() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.".to_string(),
        rule_id: "readme-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"rdme_[a-z0-9]{70}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["rdme_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("api-token", &format!("rdme_{}", secrets::new_secret(&alpha_numeric("70")))), 
    ];

    validate(rule, &test_positives, None)
}