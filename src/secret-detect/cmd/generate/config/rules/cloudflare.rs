use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - hex(length: &str) -> String
// - alpha_numeric_extended_short(length: &str) -> String
// - generate_unique_token_regex(pattern: &str, case_insensitive: bool) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

// Test data (move to appropriate testing module)
static GLOBAL_KEYS: &[&str] = &[
    r#"cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca""#, 
    r#"CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c"#,    
    r#"cloudflare: "0574b9f43978174cc2cb9a1068681225433c4""#,                 
];

static API_KEYS: &[&str] = &[
    r#"cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4""#, 
    r#"CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc"#,    
    r#"cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX""#,          
];

static ORIGIN_CA_KEYS: &[&str] = &[
    r#"CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"#,
    r#"CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed"#,
];

static IDENTIFIERS: &[&str] = &["cloudflare"];

pub fn cloudflare_global_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.".to_string(),
        rule_id: "cloudflare-global-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(IDENTIFIERS, &hex("37"), true)).unwrap(),
        tags: vec![],
        keywords: IDENTIFIERS.iter().map(|s| s.to_string()).collect(),
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let false_positives: Vec<&str> = API_KEYS.iter().chain(ORIGIN_CA_KEYS.iter()).copied().collect();

    validate(rule, GLOBAL_KEYS, Some(&false_positives))
}

pub fn cloudflare_api_key() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.".to_string(),
        rule_id: "cloudflare-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(IDENTIFIERS, &alpha_numeric_extended_short("40"), true)).unwrap(),
        tags: vec![],
        keywords: IDENTIFIERS.iter().map(|s| s.to_string()).collect(),
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let false_positives: Vec<&str> = GLOBAL_KEYS.iter().chain(ORIGIN_CA_KEYS.iter()).copied().collect();

    validate(rule, API_KEYS, Some(&false_positives))
}

pub fn cloudflare_origin_ca_key() -> Rule {
    let mut ca_identifiers = IDENTIFIERS.to_vec();
    ca_identifiers.push("v1.0-");

    // Define rule
    let rule = Rule {
        description: "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.".to_string(),
        rule_id: "cloudflare-origin-ca-key".to_string(),
        regex: Regex::new(&generate_unique_token_regex(&format!("v1.0-{}
-{}", hex("24"), hex("146")), false)).unwrap(),
        tags: vec![],
        keywords: ca_identifiers.iter().map(|s| s.to_string()).collect(),
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let false_positives: Vec<&str> = GLOBAL_KEYS.iter().chain(API_KEYS.iter()).copied().collect();

    validate(rule, ORIGIN_CA_KEYS, Some(&false_positives))
}