use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn nytimes_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.".to_string(),
        rule_id: "nytimes-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["nytimes", "new-york-times,", "newyorktimes"], &alpha_numeric_extended("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["nytimes".to_string(), "new-york-times".to_string(), "newyorktimes".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("nytimes", &secrets::new_secret(&alpha_numeric("32"))),
    ];

    validate(rule, &test_positives, None)
}