use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn beamer() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.".to_string(),
        rule_id: "beamer-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["beamer"], r"b_[a-z0-9=_\-]{44}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["beamer".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("beamer", &format!("b_{}", secrets::new_secret(&alpha_numeric_extended("44")))),
    ];

    validate(rule, &test_positives, None)
}