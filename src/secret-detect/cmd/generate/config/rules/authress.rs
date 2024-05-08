use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn authress() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.".to_string(),
        rule_id: "authress-service-client-access-key".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"(?:sc|ext|scauth|authress)_[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["sc_".to_string(), "ext_".to_string(), "scauth_".to_string(), "authress_".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let service_client_id = format!("sc_{}", alpha_numeric("10"));
    let access_key_id = alpha_numeric("4");
    let account_id = format!("acc_{}", alpha_numeric("10"));
    let signature_key = alpha_numeric_extended_short("40");

    let test_positives = vec![
        generate_sample_secret("authress", &secrets::new_secret(&format!("{}.{}.{}.{}", service_client_id, access_key_id, account_id, signature_key))),
    ];

    validate(rule, &test_positives, None)
}