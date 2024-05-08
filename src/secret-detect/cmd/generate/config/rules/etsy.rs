use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn etsy_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.".to_string(),
        rule_id: "etsy-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["etsy"], &alpha_numeric("24"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["etsy".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("etsy", &secrets::new_secret(&alpha_numeric("24"))), 
    ];

    validate(rule, &test_positives, None)
}