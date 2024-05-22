use std::fs::{self, File};
use std::io::Write;

use csv::Writer;
use tempfile::tempdir;

use crate::report::Finding;

// Function to write findings to a CSV file
pub fn write_csv(findings: &[Finding], writer: &mut impl Write) -> Result<(), csv::Error> {
    if findings.is_empty() {
        return Ok(());
    }

    let mut csv_writer = Writer::from_writer(writer);

    // Write CSV header
    csv_writer.write_record(&[
        "RuleID",
        "Commit",
        "File",
        "SymlinkFile",
        "Secret",
        "Match",
        "StartLine",
        "EndLine",
        "StartColumn",
        "EndColumn",
        "Author",
        "Message",
        "Date",
        "Email",
        "Fingerprint",
        "Tags",
    ])?;

    // Write findings data
    for finding in findings {
        csv_writer.write_record(&[
            &finding.rule_id,
            &finding.commit,
            &finding.file,
            &finding.symlink_file,
            &finding.secret,
            &finding.match_str,
            &finding.start_line.to_string(),
            &finding.end_line.to_string(),
            &finding.start_column.to_string(),
            &finding.end_column.to_string(),
            &finding.author,
            &finding.message,
            &finding.date,
            &finding.email,
            &finding.fingerprint,
            &finding.tags.join(" "),
        ])?;
    }

    // Flush the writer
    csv_writer.flush()?;
    Ok(())
}

#[test]
fn test_write_csv() {
    let tests = vec![
        (
            "simple",
            vec![Finding {
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
                fingerprint: "fingerprint".to_string(),
                tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            }],
            "tests/fixtures/csv_simple.csv",
            false,
        ),
        ("empty", vec![], "", true),
    ];

    for (test_name, findings, expected_path, want_empty) in tests {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(format!("{}.csv", test_name));
        let mut file = File::create(&file_path).unwrap();

        let result = write_csv(&findings, &mut file);
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