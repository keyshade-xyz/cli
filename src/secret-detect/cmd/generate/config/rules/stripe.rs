use regex::Regex;

use crate::config::{Allowlist, Rule};

// - alpha_numeric(length: &str) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn stripe_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.".to_string(),
        rule_id: "stripe-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"(sk|rk)_(test|live|prod)_[0-9a-z]{10,99}", true)).unwrap(),
        tags: vec![],
        keywords: vec![
            "sk_test".to_string(),
            "sk_live".to_string(),
            "sk_prod".to_string(),
            "rk_test".to_string(),
            "rk_live".to_string(),
            "rk_prod".to_string(),
        ],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("stripeToken := \"sk_test_{}\"", secrets::new_secret(&alpha_numeric("30"))),
        "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs", 
        "rk_prod_51OuEMLAlTWGaDypquDn9aZigaJOsa9NR1w1BxZXs9JlYsVVkv5XDu6aLmAxwt5Tgun5WcSwQMKzQyqV16c9iD4sx00BRijuoon", 
    ];
    let false_positives = vec![&format!("nonMatchingToken := \"task_test_{}\"", secrets::new_secret(&alpha_numeric("30")))];

    validate(rule, &test_positives, Some(&false_positives))
}