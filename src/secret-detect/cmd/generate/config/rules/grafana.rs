use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn grafana_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.".to_string(),
        rule_id: "grafana-api-key".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"eyJrIjoi[A-Za-z0-9]{70,400}={0,2}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["eyJrIjoi".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("grafana-api-key", &format!("eyJrIjoi{}", secrets::new_secret(&alpha_numeric("70")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn grafana_cloud_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.".to_string(),
        rule_id: "grafana-cloud-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"glc_[A-Za-z0-9+/]{32,400}={0,2}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["glc_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("grafana-cloud-api-token", &format!("glc_{}", secrets::new_secret(&alpha_numeric("32")))),
    ];

    validate(rule, &test_positives, None)
}

pub fn grafana_service_account_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.".to_string(),
        rule_id: "grafana-service-account-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["glsa_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("grafana-service-account-token", &format!("glsa_{}_{}", secrets::new_secret(&alpha_numeric("32")), secrets::new_secret(&hex("8")))), 
    ];

    validate(rule, &test_positives, None)
}