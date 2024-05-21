use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn postman_api() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.".to_string(),
        rule_id: "postman-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["PMAK-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("postmanAPItoken", &format!("PMAK-{}-{}", secrets::new_secret(&hex("24")), secrets::new_secret(&hex("34")))),
    ];

    validate(rule, &test_positives, None)
}