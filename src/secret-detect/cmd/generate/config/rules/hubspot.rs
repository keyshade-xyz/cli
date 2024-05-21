use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn hubspot() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.".to_string(),
        rule_id: "hubspot-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["hubspot"], r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["hubspot".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"const hubspotKey = "12345678-ABCD-ABCD-ABCD-1234567890AB""#, 
    ];

    validate(rule, &test_positives, None)
}