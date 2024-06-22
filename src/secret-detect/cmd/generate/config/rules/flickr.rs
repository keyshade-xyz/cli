use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn flickr_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.".to_string(),
        rule_id: "flickr-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["flickr"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["flickr".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("flickr", &secrets::new_secret(&alpha_numeric("32"))), 
    ];

    validate(rule, &test_positives, None)
}