use regex::Regex;

use crate::config::{Allowlist, Rule};

// - numeric(length: &str) -> String
// - alpha_numeric(length: &str) -> String
// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn slack_bot_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.".to_string(),
        rule_id: "slack-bot-token".to_string(),
        regex: Regex::new(r"(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)").unwrap(),
        tags: vec![],
        keywords: vec!["xoxb".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#""bot_token1": "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD""#, 
        r#""bot_token2": "xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS""#, 
        r#""bot_token3": "xoxb-4614724432022-5152386766518-O5WzjWGLG0wcCm2WPrjEmnys""#,   
        &format!(
            r#""bot_token4": "xoxb-{}-{}-{}""#,
            secrets::new_secret(&numeric("13")),
            secrets::new_secret(&numeric("12")),
            secrets::new_secret(&alpha_numeric("24"))
        ),
    ];
    let false_positives = vec![
        "xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx",
        "xoxb-xxx",
        "xoxb-12345-abcd234",
        "xoxb-xoxb-my-bot-token",
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_user_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.".to_string(),
        rule_id: "slack-user-token".to_string(),
        regex: Regex::new(r"(xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34})").unwrap(),
        tags: vec![],
        keywords: vec!["xoxp-".to_string(), "xoxe-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#""user_token1": "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef""#, 
        r#""user_token2": "xoxp-283316862324-298911817009-298923149681-44f585044dace54f5701618e97cd1c0b""#, 
        r#""user_token3": "xoxp-11873098179-111402824422-234336993777-b96c9fb3b69f82ebb79d12f280779de1""#, 
        r#""user_token4": "xoxp-254112160503-252950188691-252375361712-6cbf56aada30951a9d310a5f23d032a0""#,    
        r#""user_token5": "xoxp-4614724432022-4621207627011-5182682871568-1ddad9823e8528ad0f4944dfa3c6fc6c""#, 
        &format!(
            r#""user_token6": "xoxp-{}-{}-{}-{}""#,
            secrets::new_secret(&numeric("12")),
            secrets::new_secret(&numeric("13")),
            secrets::new_secret(&numeric("13")),
            secrets::new_secret(&alpha_numeric("32"))
        ),
        // It's unclear what the `xoxe-` token means in this context, however, the format is similar to a user token.
        r#""url_private": "https:\/\/files.slack.com\/files-pri\/T04MCQMEXQ9-F04MAA1PKE3\/image.png?t=xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206""#,
    ];
    let false_positives = vec![
        r#"https://docs.google.com/document/d/1W7KCxOxP-1Fy5EyF2lbJGE2WuKmu5v0suYqoHas1jRM"#,
        r#""token1": "xoxp-1234567890""#, 
        r#""token2": "xoxp-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX""#, 
        r#""token3": "xoxp-1234-1234-1234-4ddbc191d40ee098cbaae6f3523ada2d""#,                    
        r#""token4": "xoxp-572370529330-573807301142-572331691188-####################""#,        
                                                                                                  // This technically matches the pattern but is an obvious false positive.
                                                                                                  // r#""token5": "xoxp-000000000000-000000000000-000000000000-00000000000000000000000000000000""#, 
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_app_level_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.".to_string(),
        rule_id: "slack-app-token".to_string(),
        regex: Regex::new(r"(?i)(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)").unwrap(),
        tags: vec![],
        keywords: vec!["xapp".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        r#""token1": "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e""#, 
        r#""token2": "xapp-1-IEMF8IMY1OQ-4037076220459-85c370b433e366de369c4ef5abdf41253519266982439a75af74a3d68d543fb6""#, 
        r#""token3": "xapp-1-BM3V7LC51DA-1441525068281-86641a2582cd0903402ab523e5bcc53b8253098c31591e529b55b41974d2e82f""#, 
        &format!(
            r#""token4": "xapp-1-A{}-{}-{}""#,
            secrets::new_secret(&numeric("10")),
            secrets::new_secret(&numeric("13")),
            secrets::new_secret(&alpha_numeric("64"))
        ),
    ];

    validate(rule, &test_positives, None)
}

pub fn slack_configuration_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.".to_string(),
        rule_id: "slack-config-access-token".to_string(),
        regex: Regex::new(r"(?i)(xoxe.xox[bp]-\d-[A-Z0-9]{163,166})").unwrap(),
        tags: vec![],
        keywords: vec!["xoxe.xoxb-".to_string(), "xoxe.xoxp-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        r#""access_token1": "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ""#, 
        r#""access_token2": "xoxe.xoxp-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ""#, 
        &format!(
            r#""access_token3": "xoxe.xoxp-1-{}""#,
            secrets::new_secret(&alpha_numeric("163"))
        ),
        r#""access_token4": "xoxe.xoxb-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ""#,
        &format!(
            r#""access_token5": "xoxe.xoxb-1-{}""#,
            secrets::new_secret(&alpha_numeric("165"))
        ),
    ];
    let false_positives = vec![
        "xoxe.xoxp-1-SlackAppConfigurationAccessTokenHere",
        "xoxe.xoxp-1-RANDOMSTRINGHERE",
        "xoxe.xoxp-1-initial",
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_configuration_refresh_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.".to_string(),
        rule_id: "slack-config-refresh-token".to_string(),
        regex: Regex::new(r"(?i)(xoxe-\d-[A-Z0-9]{146})").unwrap(),
        tags: vec![],
        keywords: vec!["xoxe-".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        r#""refresh_token1": "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg""#, 
        r#""refresh_token2": "xoxe-1-My0xLTM0MTQwNDE0MDE3Ni01MTgyMDc1NDk2MDgwLTU0MjQ1NjIwNzgxODEtNGJkYTZhYTUxY2M1ODk3ZTNkN2YzMTgxMDI1ZDQzNzgwNWY4NWQ0ODdhZGIzM2ViOGI0MTM0MjdlNGVmYzQ4Ng""#, 
        &format!(
            r#""refresh_token3": "xoxe-1-{}""#,
            secrets::new_secret(&alpha_numeric("146"))
        ),
    ];
    let false_positives = vec!["xoxe-1-xxx", "XOxE-RROAmw, Home and Garden, 5:24, 20120323"];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_legacy_bot_token() -> Rule {
    let rule = Rule {
        description: "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.".to_string(),
        rule_id: "slack-legacy-bot-token".to_string(),
        regex: Regex::new(r"(xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26})").unwrap(),
        tags: vec![],
        keywords: vec!["xoxb".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        r#""bot_token1": "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1""#, 
        r#""bot_token2": "xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP""#, 
        r#""bot_token3": "xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1""#, 
        r#""bot_token4": "xoxb-123456789012-Xw937qtWSXJss1lFaKe""#, 
        r#""bot_token5": "xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS""#, 
        r#""bot_token6": "xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi""#, 
        r#""bot_token7": "xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK""#, 
        r#""bot_token8": "xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI""#,                                                             
        r#""bot_token9": "xoxb-50014434-slacktokenx29U9X1bQ""#,                                                                     
        &format!(
            r#""bot_token10": "xoxb-{}-{}""#,
            secrets::new_secret(&numeric("10")),
            secrets::new_secret(&alpha_numeric("24"))
        ), 
        &format!(
            r#""bot_token11": "xoxb-{}-{}""#,
            secrets::new_secret(&numeric("12")),
            secrets::new_secret(&alpha_numeric("23"))
        ), 
    ];
    let false_positives = vec![
        "xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx", 
        "xoxb-Slack_BOT_TOKEN",
        "xoxb-abcdef-abcdef",
        // "xoxb-0000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_legacy_workspace_token() -> Rule {
    let rule = Rule {
        description: "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.".to_string(),
        rule_id: "slack-legacy-workspace-token".to_string(),
        regex: Regex::new(r"(xox[ar](?:-\d-)?[0-9a-zA-Z]{8,48})").unwrap(),
        tags: vec![],
        keywords: vec!["xoxa".to_string(), "xoxr".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    let test_positives = vec![
        r#""access_token": "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c""#, 
        &format!(
            r#""access_token1": "xoxa-{}-{}""#,
            secrets::new_secret(&numeric("1")),
            secrets::new_secret(&alpha_numeric("12"))
        ),
        &format!(
            r#""access_token2": "xoxa-{}""#,
            secrets::new_secret(&alpha_numeric("12"))
        ),
        &format!(
            r#""refresh_token1": "xoxr-{}-{}""#,
            secrets::new_secret(&numeric("1")),
            secrets::new_secret(&alpha_numeric("12"))
        ),
        &format!(
            r#""refresh_token2": "xoxr-{}""#,
            secrets::new_secret(&alpha_numeric("12"))
        ),
    ];
    let false_positives = vec![
        // "xoxa-faketoken",
        // "xoxa-access-token-string",
        // "XOXa-nx991k",
        "https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md",
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_legacy_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.".to_string(),
        rule_id: "slack-legacy-token".to_string(),
        regex: Regex::new(r"(xox[os]-\d+-\d+-\d+-[a-fA-F\d]+)").unwrap(),
        tags: vec![],
        keywords: vec!["xoxo".to_string(), "xoxs".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#""access_token1": "xoxs-3206092076-3204538285-3743137121-836b042620""#, 
        r#""access_token2": "xoxs-416843729158-132049654-5609968301-e708ba56e1""#, 
        r#""access_token3": "xoxs-420083410720-421837374423-440811613314-977844f625b707d5b0b268206dbc92cbc85feef3e71b08e44815a8e6e7657190""#, 
        r#""access_token4": "xoxs-4829527689-4829527691-4814341714-d0346ec616""#, 
        r#""access_token5": "xoxs-155191149137-155868813314-338998331396-9f6d235915""#, 
        &format!(
            r#""access_token6": "xoxs-{}-{}-{}-{}""#,
            secrets::new_secret(&numeric("10")),
            secrets::new_secret(&numeric("10")),
            secrets::new_secret(&numeric("10")),
            secrets::new_secret(&hex("10"))
        ),
        r#""access_token7": "xoxo-523423-234243-234233-e039d02840a0b9379c""#, 
    ];
    let false_positives = vec![
        "https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg",
        "https://lh3.googleusercontent.com/-tWXjX3LUD6w/Ua4La_N5E2I/AAAAAAAAACg/qcm19xbEYa4/s640/EXO-XOXO-teaser-exo-k-34521098-720-516.jpg",
    ];

    validate(rule, &test_positives, Some(&false_positives))
}

pub fn slack_webhook_url() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.".to_string(),
        rule_id: "slack-webhook-url".to_string(),
        regex: Regex::new(r"(https?:\/\/)?hooks.slack.com\/(services|workflows)\/[A-Za-z0-9+\/]{43,46}").unwrap(),
        tags: vec![],
        keywords: vec!["hooks.slack.com".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        &format!("hooks.slack.com/services/{}", secrets::new_secret(&alpha_numeric("44"))),
        &format!("http://hooks.slack.com/services/{}", secrets::new_secret(&alpha_numeric("45"))),
        &format!("https://hooks.slack.com/services/{}", secrets::new_secret(&alpha_numeric("46"))),
        "http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555",   
        "https://hooks.slack.com/services/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", 
        &format!("hooks.slack.com/workflows/{}", secrets::new_secret(&alpha_numeric("44"))),
        &format!("http://hooks.slack.com/workflows/{}", secrets::new_secret(&alpha_numeric("45"))),
        &format!("https://hooks.slack.com/workflows/{}", secrets::new_secret(&alpha_numeric("46"))),
        "https://hooks.slack.com/workflows/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", 
        "http://hooks.slack.com/workflows/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",    
    ];

    validate(rule, &test_positives, None)
}