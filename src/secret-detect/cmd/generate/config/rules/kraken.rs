use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric_extended_long(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn kraken_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.".to_string(),
        rule_id: "kraken-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["kraken"], &alpha_numeric_extended_long("80,90"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["kraken".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("kraken", &secrets::new_secret(&alpha_numeric_extended_long("80,90"))),
    ];

    validate(rule, &test_positives, None)
}