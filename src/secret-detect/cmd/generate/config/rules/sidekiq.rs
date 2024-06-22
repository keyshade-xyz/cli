use regex::Regex;

use crate::config::{Allowlist, Rule};

// - generate_semi_generic_regex(prefixes: &[&str], suffix: &str, case_insensitive: bool) -> String
// - validate(rule: Rule, test_positives: &[&str], test_negatives: Option<&[&str]>) -> Rule 

pub fn sidekiq_secret() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.".to_string(),
        rule_id: "sidekiq-secret".to_string(),
        regex: Regex::new(&generate_semi_generic_regex(&["BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"], r"[a-f0-9]{8}:[a-f0-9]{8}", true)).unwrap(),
        tags: vec![],
        keywords: vec!["BUNDLE_ENTERPRISE__CONTRIBSYS__COM".to_string(), "BUNDLE_GEMS__CONTRIBSYS__COM".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: None,
    };

    // Validate
    let test_positives = vec![
        "BUNDLE_ENTERPRISE__CONTRIBSYS__COM: cafebabe:deadbeef",
        "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
        "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM = cafebabe:deadbeef",
        r#"BUNDLE_GEMS__CONTRIBSYS__COM: "cafebabe:deadbeef""#,
        r#"export BUNDLE_GEMS__CONTRIBSYS__COM="cafebabe:deadbeef""#,
        r#"export BUNDLE_GEMS__CONTRIBSYS__COM = "cafebabe:deadbeef""#,
        "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
        "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef && echo 'hello world'",
    ];

    validate(rule, &test_positives, None)
}

pub fn sidekiq_sensitive_url() -> Rule {
    // Define rule
    let rule = Rule {
        description: "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.".to_string(),
        rule_id: "sidekiq-sensitive-url".to_string(),
        regex: Regex::new(r"(?i)\b(http(?:s??):\/\/)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)").unwrap(),
        tags: vec![],
        keywords: vec!["gems.contribsys.com".to_string(), "enterprise.contribsys.com".to_string()],
        allowlist: Allowlist::default(),
        entropy: None,
        secret_group: Some(2),
    };

    // Validate
    let test_positives = vec![
        "https://cafebabe:deadbeef@gems.contribsys.com/",
        "https://cafebabe:deadbeef@gems.contribsys.com",
        "https://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
        "https://cafeb4b3:d3adb33f@enterprise.contribsys.com",
        "http://cafebabe:deadbeef@gems.contribsys.com/",
        "http://cafebabe:deadbeef@gems.contribsys.com",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com/",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com#heading1",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com?param1=true¶m2=false",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80",
        "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true¶m2=false#heading1",
    ];

    validate(rule, &test_positives, None)
}