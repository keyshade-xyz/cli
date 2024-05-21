use regex::Regex;

use crate::config::{Allowlist, Rule};

// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn teams_webhook() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.".to_string(),
        rule_id: "microsoft-teams-webhook".to_string(),
        regex: Regex::new(r"https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}").unwrap(),
        tags: vec![],
        keywords: vec![
            "webhook.office.com".to_string(), 
            "webhookb2".to_string(), 
            "IncomingWebhook".to_string(),
        ],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![&format!("https://mycompany.webhook.office.com/webhookb2/{}", secrets::new_secret(r"[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}"))]; // gitleaks:allow

    validate(rule, &test_positives, None)
}