use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn jfrog_api_key() -> Rule {
    let keywords = vec!["jfrog".to_string(), "artifactory".to_string(), "bintray".to_string(), "xray".to_string()];

    // Define rule
    let rule = Rule {
        description: "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.".to_string(),
        rule_id: "jfrog-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&keywords, &alpha_numeric("73"), true)).unwrap(),
        tags: vec![],
        keywords,
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        format!("--set imagePullSecretJfrog.password={}", secrets::new_secret(&alpha_numeric("73"))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn jfrog_identity_token() -> Rule {
    let keywords = vec!["jfrog".to_string(), "artifactory".to_string(), "bintray".to_string(), "xray".to_string()];

    // Define rule
    let rule = Rule {
        description: "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.".to_string(),
        rule_id: "jfrog-identity-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&keywords, &alpha_numeric("64"), true)).unwrap(),
        tags: vec![],
        keywords: keywords.clone(),
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("jfrog", &secrets::new_secret(&alpha_numeric("64"))),
        generate_sample_secret("artifactory", &secrets::new_secret(&alpha_numeric("64"))),
        generate_sample_secret("bintray", &secrets::new_secret(&alpha_numeric("64"))),
        generate_sample_secret("xray", &secrets::new_secret(&alpha_numeric("64"))),
    ];

    validate(rule, &test_positives, None)
}