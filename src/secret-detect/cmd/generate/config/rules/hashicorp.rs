use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - alpha_numeric_extended(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn hashicorp() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.".to_string(),
        rule_id: "hashicorp-tf-api-token".to_string(),
        regex: Regex::new(r"(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}").unwrap(),
        tags: vec![],
        keywords: vec!["atlasv1".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("hashicorpToken", &format!("{}.atlasv1.{}", secrets::new_secret(&hex("14")), secrets::new_secret(&alpha_numeric_extended("60,70")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn hashicorp_field() -> Rule {
    let keywords = vec!["administrator_login_password".to_string(), "password".to_string()];
    
    // Define rule
    let rule = Rule {
        description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.".to_string(),
        rule_id: "hashicorp-tf-password".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&keywords, &format!(r#""{}""#, alpha_numeric_extended("8,20")), true)).unwrap(),
        tags: vec![],
        keywords: keywords.clone(),
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        // Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
        &format!("administrator_login_password = {}", r#""thisIsDog11""#),
        // https://registry.terraform.io/providers/petoju/mysql/latest/docs
        &format!("password       = {}", r#""rootpasswd""#),
    ];
    let false_positives = vec![
        "administrator_login_password = var.db_password",
        r#"password = "${aws_db_instance.default.password}""#,
    ];

    validate(rule, &test_positives, Some(&false_positives))
}