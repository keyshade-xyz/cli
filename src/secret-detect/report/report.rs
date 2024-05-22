use std::{fs::{self,File}, io::Write, path::Path};

use tempfile::tempdir;

use crate::config::Config;
use crate::report::{Finding, write_csv, write_json, write_junit, write_report};

pub const CWE: &str = "CWE-798";
pub const CWE_DESCRIPTION: &str = "Use of Hard-coded Credentials";

// Function to write the report in the specified format
pub fn write_report(
    findings: &[Finding],
    config: &Config,
    extension: &str,
    report_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(report_path)?;
    let ext = extension.to_lowercase();

    match ext.as_str() {
        "json" | ".json" => write_json(findings, &mut file),
        "csv" | ".csv" => write_csv(findings, &mut file),
        "xml" | "junit" | ".xml" => write_junit(findings, &mut file),
        "sarif" | ".sarif" => write_sarif(config, findings, &mut file),
        _ => Err(format!("Unsupported report format: {}", extension).into()),
    }
}


#[test]
fn test_write_report() {
    let tests = vec![
        (
            "json",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            ".json",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            ".jsonj",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            true,
        ),
        (
            ".csv",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            "csv",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            "CSV",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            ".xml",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
        (
            "junit",
            vec![Finding {
                rule_id: "test-rule".to_string(),
                ..Default::default()
            }],
            false,
        ),
    ];

    for (i, (extension, findings, want_empty)) in tests.iter().enumerate() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(format!("{}{}", i, extension));

        let result = write_report(
            &findings,
            &Config::default(),
            extension,
            &file_path,
        );
        assert!(result.is_ok());

        assert!(file_path.exists());

        let got = fs::read_to_string(&file_path).unwrap();

        if *want_empty {
            assert!(got.is_empty());
        } else {
            assert!(!got.is_empty());
        }
    }
}