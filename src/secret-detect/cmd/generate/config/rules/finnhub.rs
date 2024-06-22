use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn finnhub_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.".to_string(),
        rule_id: "finnhub-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["finnhub"], &alpha_numeric("20"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["finnhub".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("finnhub", &secrets::new_secret(&alpha_numeric("20"))), 
    ];

    validate(rule, &test_positives, None)
}