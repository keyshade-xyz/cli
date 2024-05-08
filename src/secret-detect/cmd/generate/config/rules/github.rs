use regex::Regex;

use crate::config::{Allowlist, Rule};

// Assuming the following functions exist (based on the Golang code):
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn github_pat() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.".to_string(),
        rule_id: "github-pat".to_string(),
        regex: Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
        tags: vec![],
        keywords: vec!["ghp_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("github", &format!("ghp_{}", secrets::new_secret(&alpha_numeric("36")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn github_fine_grained_pat() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.".to_string(),
        rule_id: "github-fine-grained-pat".to_string(),
        regex: Regex::new(r"github_pat_[0-9a-zA-Z_]{82}").unwrap(),
        tags: vec![],
        keywords: vec!["github_pat_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("github", &format!("github_pat_{}", secrets::new_secret(&alpha_numeric("82")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn github_oauth() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.".to_string(),
        rule_id: "github-oauth".to_string(),
        regex: Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
        tags: vec![],
        keywords: vec!["gho_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("github", &format!("gho_{}", secrets::new_secret(&alpha_numeric("36")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn github_app() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.".to_string(),
        rule_id: "github-app-token".to_string(),
        regex: Regex::new(r"(ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
        tags: vec![],
        keywords: vec!["ghu_".to_string(), "ghs_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("github", &format!("ghu_{}", secrets::new_secret(&alpha_numeric("36")))), 
        generate_sample_secret("github", &format!("ghs_{}", secrets::new_secret(&alpha_numeric("36")))), 
    ];

    validate(rule, &test_positives, None)
}

pub fn github_refresh() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.".to_string(),
        rule_id: "github-refresh-token".to_string(),
        regex: Regex::new(r"ghr_[0-9a-zA-Z]{36}").unwrap(),
        tags: vec![],
        keywords: vec!["ghr_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("github", &format!("ghr_{}", secrets::new_secret(&alpha_numeric("36")))),
    ];

    validate(rule, &test_positives, None)
}