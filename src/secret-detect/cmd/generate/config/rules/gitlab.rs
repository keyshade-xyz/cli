use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn gitlab_pat() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.".to_string(),
        rule_id: "gitlab-pat".to_string(),
        regex: Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap(),
        tags: vec![],
        keywords: vec!["glpat-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gitlab", &format!("glpat-{}", secrets::new_secret(&alpha_numeric("20")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn gitlab_pipeline_trigger_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.".to_string(),
        rule_id: "gitlab-ptt".to_string(),
        regex: Regex::new(r"glptt-[0-9a-f]{40}").unwrap(),
        tags: vec![],
        keywords: vec!["glptt-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gitlab", &format!("glptt-{}", secrets::new_secret(&hex("40")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn gitlab_runner_registration_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.".to_string(),
        rule_id: "gitlab-rrt".to_string(),
        regex: Regex::new(r"GR1348941[0-9a-zA-Z\-_]{20}").unwrap(),
        tags: vec![],
        keywords: vec!["GR1348941".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("gitlab", &format!("GR1348941{}", secrets::new_secret(&alpha_numeric("20")))),
    ];

    validate(rule, &test_positives, None)
}