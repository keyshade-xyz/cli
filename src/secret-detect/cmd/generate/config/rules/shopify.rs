use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn shopify_shared_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.".to_string(),
        rule_id: "shopify-shared-secret".to_string(),
        regex: Regex::new(r"shpss_[a-fA-F0-9]{32}").unwrap(),
        tags: vec![],
        keywords: vec!["shpss_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!("shopifySecret := \"shpss_{}\"", secrets::new_secret(&hex("32")))];

    validate(rule, &test_positives, None)
}

pub fn shopify_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.".to_string(),
        rule_id: "shopify-access-token".to_string(),
        regex: Regex::new(r"shpat_[a-fA-F0-9]{32}").unwrap(),
        tags: vec![],
        keywords: vec!["shpat_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!("shopifyToken := \"shpat_{}\"", secrets::new_secret(&hex("32")))];

    validate(rule, &test_positives, None)
}

pub fn shopify_custom_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.".to_string(),
        rule_id: "shopify-custom-access-token".to_string(),
        regex: Regex::new(r"shpca_[a-fA-F0-9]{32}").unwrap(),
        tags: vec![],
        keywords: vec!["shpca_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!("shopifyToken := \"shpca_{}\"", secrets::new_secret(&hex("32")))];

    validate(rule, &test_positives, None)
}

pub fn shopify_private_app_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.".to_string(),
        rule_id: "shopify-private-app-access-token".to_string(),
        regex: Regex::new(r"shppa_[a-fA-F0-9]{32}").unwrap(),
        tags: vec![],
        keywords: vec!["shppa_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!("shopifyToken := \"shppa_{}\"", secrets::new_secret(&hex("32")))];

    validate(rule, &test_positives, None)
}