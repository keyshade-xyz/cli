use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex8_4_4_4_12() -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn snyk() -> Rule {
    let keywords = vec![
        "snyk_token".to_string(),
        "snyk_key".to_string(),
        "snyk_api_token".to_string(),
        "snyk_api_key".to_string(),
        "snyk_oauth_token".to_string(),
    ];

    // Define rule
    let rule = Rule {
        description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.".to_string(),
        rule_id: "snyk-api-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&keywords, &hex8_4_4_4_12(), true)).unwrap(),
        tags: vec![],
        keywords,
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB""#, 
        r#"const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB""#,   
        r#"SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB""#,      
        r#"SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB""#,     
        r#"SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB""#,    
        r#"SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB""#,      
        r#"SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB""#,    
        r#"SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB""#,   
        r#"SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB""#, 
    ];

    validate(rule, &test_positives, None)
}