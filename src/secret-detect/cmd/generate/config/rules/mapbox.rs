use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn mapbox() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.".to_string(),
        rule_id: "mapbox-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["mapbox"], r"pk\.[a-z0-9]{60}\.[a-z0-9]{22}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["mapbox".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mapbox", &format!("pk.{}.{}", secrets::new_secret(&alpha_numeric("60")), secrets::new_secret(&alpha_numeric("22")))),
    ];

    validate(rule, &test_positives, None)
}