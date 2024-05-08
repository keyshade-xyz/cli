use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn clojars() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.".to_string(),
        rule_id: "clojars-api-token".to_string(),
        regex: Regex::new(r"(?i)(CLOJARS_)[a-z0-9]{60}").unwrap(),
        tags: vec![],
        keywords: vec!["clojars".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("clojars", &format!("CLOJARS_{}", secrets::new_secret(&alpha_numeric("60")))),
    ];

    validate(rule, &test_positives, None)
}