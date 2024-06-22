use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn yandex_aws_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.".to_string(),
        rule_id: "yandex-aws-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["yandex"], r"YC[a-zA-Z0-9_\-]{38}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["yandex".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("yandex", &secrets::new_secret(r"YC[a-zA-Z0-9_\-]{38}")), 
    ];

    validate(rule, &test_positives, None)
}

pub fn yandex_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.".to_string(),
        rule_id: "yandex-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["yandex"], r"AQVN[A-Za-z0-9_\-]{35,38}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["yandex".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("yandex", &secrets::new_secret(r"AQVN[A-Za-z0-9_\-]{35,38}")), 
    ];

    validate(rule, &test_positives, None)
}

pub fn yandex_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.".to_string(),
        rule_id: "yandex-access-token".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["yandex"], r"t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["yandex".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("yandex", &secrets::new_secret(r"t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}")), 
    ];

    validate(rule, &test_positives, None)
}