use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn bittrex_access_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.".to_string(),
        rule_id: "bittrex-access-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["bittrex"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["bittrex".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("bittrex", &secrets::new_secret(&alpha_numeric("32"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn bittrex_secret_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.".to_string(),
        rule_id: "bittrex-secret-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["bittrex"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["bittrex".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("bittrex", &secrets::new_secret(&alpha_numeric("32"))), 
    ];

    validate(rule, &test_positives, None)
}