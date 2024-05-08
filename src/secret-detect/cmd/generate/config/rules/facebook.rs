use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - alpha_numeric(length: &str) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn facebook_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.".to_string(),
        rule_id: "facebook-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["facebook"], &hex("32"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["facebook".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("facebook", &secrets::new_secret(&hex("32"))), 
        r#"facebook_app_secret = "6dca6432e45d933e13650d1882bd5e69""#, 
        r#"facebook_client_access_token: 26f5fd13099f2c1331aafb86f6489692"#, 
    ];

    validate(rule, &test_positives, None)
}

pub fn facebook_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.".to_string(),
        rule_id: "facebook-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"\d{15,16}\|[0-9a-z\-_]{27}", true)).unwrap(),
        tags: vec![],
        keywords: vec![],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"{"access_token":"911602140448729|AY-lRJZq9BoDLobvAiP25L7RcMg","token_type":"bearer"}"#, 
        r#"1308742762612587|rhoK1cbv0DOU_RTX_87O4MkX7AI"#,                                         
        r#"1477036645700765|wRPf2v3mt2JfMqCLK8n7oltrEmc"#,                                         
    ];

    validate(rule, &test_positives, None)
}

pub fn facebook_page_access_token() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.".to_string(),
        rule_id: "facebook-page-access-token".to_string(),
        regex: Regex::new(&generate_unique_token_regex(r"EAA[MC]".to_string() + &alpha_numeric("20,"), true)).unwrap(),
        tags: vec![],
        keywords: vec!["EAAM".to_string(), "EAAC".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        r#"EAAM9GOnCB9kBO2frzOAWGN2zMnZClQshlWydZCrBNdodesbwimx1mfVJgqZBP5RSpMfUzWhtjTTXHG5I1UlvlwRZCgjm3ZBVGeTYiqAAoxyED6HaUdhpGVNoPUwAuAWWFsi9OvyYBQt22DGLqMIgD7VktuCTTZCWKasz81Q822FPhMTB9VFFyClNzQ0NLZClt9zxpsMMrUZCo1VU1rL3CKavir5QTfBjfCEzHNlWAUDUV2YZD"#, // gitleaks:allow
        r#"EAAM9GOnCB9kBO2zXpAtRBmCrsPPjdA3KeBl4tqsEpcYd09cpjm9MZCBIklZBjIQBKGIJgFwm8IE17G5pipsfRBRBEHMWxvJsL7iHLUouiprxKRQfAagw8BEEDucceqxTiDhVW2IZAQNNbf0d1JhcapAGntx5S1Csm4j0GgZB3DuUfI2HJ9aViTtdfH2vjBy0wtpXm2iamevohGfoF4NgyRHusDLjqy91uYMkfrkc"#,          // gitleaks:allow
        r#"- name: FACEBOOK_TOKEN
		value: "EAACEdEose0cBA1bad3afsf2aew""#, 
    ];

    validate(rule, &test_positives, None)
}