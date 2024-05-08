use regex::Regex;
use std::collections::HashMap;

use crate::config::{Config, Rule};
use crate::detect::Detector;

//TODO: Fix regex pattern errors

// Constants for regular expression patterns
const CASE_INSENSITIVE: &str = r"(?i)";
const IDENTIFIER_CASE_INSENSITIVE_PREFIX: &str = r"(?i:";
const IDENTIFIER_CASE_INSENSITIVE_SUFFIX: &str = r")";
const IDENTIFIER_PREFIX: &str = r"(?:";
const IDENTIFIER_SUFFIX: &str = r")(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}";
const OPERATOR: &str = r"(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=) ";
const SECRET_PREFIX_UNIQUE: &str = r"\b(";
const SECRET_PREFIX: &str = r"(?:'|\"|\s|=|\x60){0,5}( ";
const SECRET_SUFFIX: &str = r")(?:['|\"|\n|\r|\s|\x60|;]|$) ";

// Function to generate a semi-generic regex pattern
pub fn generate_semi_generic_regex(identifiers: &[&str], secret_regex: &str, case_insensitive: bool) -> String {
    let mut pattern = String::new();

    if case_insensitive {
        pattern.push_str(CASE_INSENSITIVE);
        write_identifiers(&mut pattern, identifiers);
    } else {
        pattern.push_str(IDENTIFIER_CASE_INSENSITIVE_PREFIX);
        write_identifiers(&mut pattern, identifiers);
        pattern.push_str(IDENTIFIER_CASE_INSENSITIVE_SUFFIX);
    }

    pattern.push_str(OPERATOR);
    pattern.push_str(SECRET_PREFIX);
    pattern.push_str(secret_regex);
    pattern.push_str(SECRET_SUFFIX);

    pattern
}

// Helper function to write identifiers to the pattern string
fn write_identifiers(pattern: &mut String, identifiers: &[&str]) {
    pattern.push_str(IDENTIFIER_PREFIX);
    pattern.push_str(&identifiers.join("|"));
    pattern.push_str(IDENTIFIER_SUFFIX);
}

// Function to generate a unique token regex pattern
pub fn generate_unique_token_regex(secret_regex: &str, case_insensitive: bool) -> String {
    let mut pattern = String::new();

    if case_insensitive {
        pattern.push_str(CASE_INSENSITIVE);
    }

    pattern.push_str(SECRET_PREFIX_UNIQUE);
    pattern.push_str(secret_regex);
    pattern.push_str(SECRET_SUFFIX);

    pattern
}

// Function to generate a sample secret for testing
pub fn generate_sample_secret(identifier: &str, secret: &str) -> String {
    format!("{}_api_token = \"{}\"", identifier, secret)
}

// Function to validate a rule using test positives and negatives
pub fn validate(rule: Rule, true_positives: &[&str], false_positives: Option<&[&str]>) -> Rule {
    // Normalize keywords
    let keywords: Vec<String> = rule.keywords.iter().map(|k| k.to_lowercase()).collect();

    let mut rules = HashMap::new();
    rules.insert(rule.rule_id.clone(), rule.clone());

    let config = Config {
        rules,
        keywords: keywords.clone(),
        ..Default::default()
    };

    let detector = Detector::new(config);

    for tp in true_positives {
        let detections = detector.detect_string(tp);
        if detections.len() != 1 {
            panic!("Failed to validate rule: {} - True positive not detected: {}", rule.rule_id, tp);
        }
    }

    if let Some(false_positives) = false_positives {
        for fp in false_positives {
            let detections = detector.detect_string(fp);
            if !detections.is_empty() {
                panic!("Failed to validate rule: {} - False positive detected: {}", rule.rule_id, fp);
            }
        }
    }

    rule
}

// Helper functions to generate regex patterns for specific formats
pub fn numeric(size: &str) -> String {
    format!("[0-9]{{{}}}", size)
}

pub fn hex(size: &str) -> String {
    format!("[a-f0-9]{{{}}}", size)
}

pub fn alpha_numeric(size: &str) -> String {
    format!("[a-z0-9]{{{}}}", size)
}

pub fn alpha_numeric_extended_short(size: &str) -> String {
    format!("[a-z0-9_-]{{{}}}", size)
}

pub fn alpha_numeric_extended(size: &str) -> String {
    format!("[a-z0-9=_\-]{{{}}}", size)
}

pub fn alpha_numeric_extended_long(size: &str) -> String {
    format!("[a-z0-9\/=_\+\-]{{{}}}", size)
}

pub fn hex8_4_4_4_12() -> String {
    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}".to_string()
}