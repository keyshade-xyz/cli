use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn rubygems_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.".to_string(),
        rule_id: "rubygems-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"rubygems_[a-f0-9]{48}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["rubygems_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("rubygemsAPIToken", &format!("rubygems_{}", secrets::new_secret(&hex("48")))),
    ];

    validate(rule, &test_positives, None)
}