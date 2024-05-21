use regex::Regex;

use crate::config::{Allowlist, Rule};

// - hex(length: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn twilio() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data.".to_string(),
        rule_id: "twilio-api-key".to_string(),
        regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
        tags: vec![],
        keywords: vec!["twilio".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("twilioAPIKey := \"SK{}
\"", secrets::new_secret(&hex("32"))), 
    ];

    validate(rule, &test_positives, None)
}