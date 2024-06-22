use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn pypi_upload_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.".to_string(),
        rule_id: "pypi-upload-token".to_string(),
        regex: Regex::new(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}").unwrap(),
        tags: vec![],
        keywords: vec!["pypi-AgEIcHlwaS5vcmc".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!(
        "pypiToken := \"pypi-AgEIcHlwaS5vcmc{}{}\"",
        secrets::new_secret(&hex("32")),
        secrets::new_secret(&hex("32"))
    )];

    validate(rule, &test_positives, None)
}