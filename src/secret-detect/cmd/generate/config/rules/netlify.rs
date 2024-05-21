use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn netlify_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.".to_string(),
        rule_id: "netlify-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["netlify"], &alpha_numeric_extended("40,46"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["netlify".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("netlify", &secrets::new_secret(&alpha_numeric_extended("40,46"))),
    ];

    validate(rule, &test_positives, None)
}