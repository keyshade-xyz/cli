use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn mailchimp() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.".to_string(),
        rule_id: "mailchimp-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["MailchimpSDK.initialize", "mailchimp"], &format!("{}
-us\\d\\d", hex("32")), true)).unwrap(),
        tags: vec![],
        keywords: vec!["mailchimp".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("mailchimp", &format!("{}
-us20", secrets::new_secret(&hex("32")))),
        r#"mailchimp_api_key: cefa780880ba5f5696192a34f6292c35-us18"#, 
        r#"MAILCHIMPE_KEY = "b5b9f8e50c640da28993e8b6a48e3e53-us18""#, 
    ];
    let false_positives = vec![
        // False Negative
        r#"MailchimpSDK.initialize(token: 3012a5754bbd716926f99c028f7ea428-us18)"#, 
    ];

    validate(rule, &test_positives, Some(&false_positives))
}