use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn pulumi_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.".to_string(),
        rule_id: "pulumi-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"pul-[a-f0-9]{40}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["pul-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("pulumi-api-token", &format!("pul-{}", secrets::new_secret(&hex("40")))), 
    ];

    validate(rule, &test_positives, None)
}