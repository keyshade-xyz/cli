use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - alpha_numeric(length: &str) -> String
// - generate_sample_secret(prefix: &str, secret: &str) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn generic_credential() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.".to_string(),
        rule_id: "generic-api-key".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["key", "api", "token", "secret", "client", "passwd", "password", "auth", "access"], r"[0-9a-z\-_.=]{10,150}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["key".to_string(), "api".to_string(), "token".to_string(), "secret".to_string(), "client".to_string(), "passwd".to_string(), "password".to_string(), "auth".to_string(), "access".to_string()],
        allowlist: Allowlist {
            stop_words: DefaultStopWords, // Assuming DefaultStopWords is defined elsewhere
            ..Allowlist::default()
        },
        entropy: Some(3.5),
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        generate_sample_secret("generic", "CLOJARS_34bf0e88955ff5a1c328d6a7491acc4f48e865a7b8dd4d70a70749037443"),
        generate_sample_secret("generic", "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"),

        //TODO: Fix Regex
        r#""client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506""#,
        r#""client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",",
    ];
    let false_positives = vec![
        r#"client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id"#,
        r#"password combination.

R5: Regulatory--21"#,
    ];

    validate(rule, &test_positives, Some(&false_positives))
}