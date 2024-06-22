use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sendinblue_api_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.".to_string(),
        rule_id: "sendinblue-api-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"xkeysib-[a-f0-9]{64}-(?i)[a-z0-9]{16}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["xkeysib-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("sendinblue", &format!("xkeysib-{}-{}", secrets::new_secret(&hex("64")), secrets::new_secret(&alpha_numeric("16")))),
    ];

    validate(rule, &test_positives, None)
}