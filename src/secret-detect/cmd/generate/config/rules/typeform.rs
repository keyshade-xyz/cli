use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn typeform() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.".to_string(),
        rule_id: "typeform-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["typeform"], r"tfp_[a-z0-9\-_\.=]{59}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["tfp_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("typeformAPIToken", &format!("tfp_{}", secrets::new_secret(&alpha_numeric_extended("59")))),
    ];

    validate(rule, &test_positives, None)
}