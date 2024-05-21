use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn launchdarkly_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.".to_string(),
        rule_id: "launchdarkly-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["launchdarkly"], &alpha_numeric_extended("40"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["launchdarkly".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("launchdarkly", &secrets::new_secret(&alpha_numeric_extended("40"))),
    ];

    validate(rule, &test_positives, None)
}