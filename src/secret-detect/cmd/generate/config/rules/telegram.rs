use regex::Regex;

use crate::config::{Allowlist, Rule};

// - numeric(length: &str) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn telegram_bot_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.".to_string(),
        rule_id: "telegram-bot-api-token".to_string(),
        regex: Regex::new(r"(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])").unwrap(),
        tags: vec![],
        keywords: vec![
            "telegram".to_string(),
            "api".to_string(),
            "bot".to_string(),
            "token".to_string(),
            "url".to_string(),
        ],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let valid_token = secrets::new_secret(&(numeric("8") + ":A" + alpha_numeric_extended_short("34")));
    let min_token = secrets::new_secret(&(numeric("5") + ":A" + alpha_numeric_extended_short("34")));
    let max_token = secrets::new_secret(&(numeric("16") + ":A" + alpha_numeric_extended_short("34")));
    let test_positives = vec![
        generate_sample_secret("telegram", &valid_token),
        generate_sample_secret("url", &format!("https://api.telegram.org/bot{}/sendMessage", valid_token)),
        &format!("const bot = new Telegraf(\"{}\")", valid_token),
        &format!("API_TOKEN = {}", valid_token),
        &format!("bot: {}", valid_token),
        generate_sample_secret("telegram", &min_token),
        generate_sample_secret("telegram", &max_token),
    ];

    let too_small_token = secrets::new_secret(&(numeric("4") + ":A" + alpha_numeric_extended_short("34")));
    let too_big_token = secrets::new_secret(&(numeric("17") + ":A" + alpha_numeric_extended_short("34")));
    let false_positives = vec![
        generate_sample_secret("telegram", &too_small_token),
        generate_sample_secret("telegram", &too_big_token),
    ];

    validate(rule, &test_positives, Some(&false_positives))
}