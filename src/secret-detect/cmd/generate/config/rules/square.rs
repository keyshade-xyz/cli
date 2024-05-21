use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn square_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.".to_string(),
        rule_id: "square-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"(EAAA|sq0atp-)[0-9A-Za-z\-_]{22,60}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["sq0atp-".to_string(), "EAAA".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("square", &secrets::new_secret(r"sq0atp-[0-9A-Za-z\-_]{22}")), 
        "ARG token=sq0atp-812erere3wewew45678901",                                    
        "ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E",
    ];

    validate(rule, &test_positives, None)
}

pub fn square_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Square Secret".to_string(),
        rule_id: "square-secret".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"sq0csp-[0-9A-Za-z\\-_]{43}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["sq0csp-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("square", &secrets::new_secret(r"sq0csp-[0-9A-Za-z\\-_]{43}")),
        r#"value: "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY""#, 
    ];

    validate(rule, &test_positives, None)
}