use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn openai() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.".to_string(),
        rule_id: "openai-api-key".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["T3BlbkFJ".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("openaiApiKey", &format!("sk-{T3BlbkFJ{}", secrets::new_secret(&alpha_numeric("20")), secrets::new_secret(&alpha_numeric("20")))),
    ];

    validate(rule, &test_positives, None)
}