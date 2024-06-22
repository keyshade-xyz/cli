use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn bitbucket_client_id() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.".to_string(),
        rule_id: "bitbucket-client-id".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["bitbucket"], &alpha_numeric("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["bitbucket".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("bitbucket", &secrets::new_secret(&alpha_numeric("32"))),
    ];

    validate(rule, &test_positives, None)
}

pub fn bitbucket_client_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.".to_string(),
        rule_id: "bitbucket-client-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["bitbucket"], &alpha_numeric_extended("64"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["bitbucket".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("bitbucket", &secrets::new_secret(&alpha_numeric("64"))),
    ];

    validate(rule, &test_positives, None)
}