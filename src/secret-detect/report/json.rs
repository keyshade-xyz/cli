use std::fs::{self, File};
use std::io::Write;

use serde_json::{ser::PrettyFormatter, to_writer_pretty};
use tempfile::tempdir;

use crate::report::Finding;

// Function to write findings to a JSON file
pub fn write_json(findings: &[Finding], writer: &mut impl Write) -> Result<(), serde_json::Error> {
    if findings.is_empty() {
        // Serialize an empty array if no findings
        to_writer_pretty(writer, &Vec::<Finding>::new())
    } else {
        // Serialize with indentation
        let formatter = PrettyFormatter::with_indent(b"  ");
        to_writer_pretty(writer, findings)
    }
}

#[test]
fn test_write_json() {
    let tests = vec![
        (
            "simple",
            vec![Finding {
                description: "".to_string(),
                rule_id: "test-rule".to_string(),
                match_str: "line containing secret".to_string(),
                secret: "a secret".to_string(),
                start_line: 1,
                end_line: 2,
                start_column: 1,
                end_column: 2,
                message: "opps".to_string(),
                file: "auth.py".to_string(),
                symlink_file: "".to_string(),
                commit: "0000000000000000".to_string(),
                author: "John Doe".to_string(),
                email: "johndoe@gmail.com".to_string(),
                date: "10-19-2003".to_string(),
                tags: vec![],
                ..Default::default()
            }],
            "tests/fixtures/json_simple.json",
            false,
        ),
        ("empty", vec![], "tests/fixtures/empty.json", false), 
    ];

    for (test_name, findings, expected_path, want_empty) in tests {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(format!("{}.json", test_name));
        let mut file = File::create(&file_path).unwrap();

        let result = write_json(&findings, &mut file);
        assert!(result.is_ok());

        assert!(file_path.exists());

        let got = fs::read_to_string(&file_path).unwrap();

        if want_empty {
            assert!(got.is_empty());
        } else {
            let want = fs::read_to_string(expected_path).unwrap();
            assert_eq!(want, got);
        }
    }
}