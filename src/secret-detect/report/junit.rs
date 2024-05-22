use std::fs::{self, File};
use std::io::Write;

use quick_xml::{
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
    Writer,
};
use serde_json::to_string_pretty;
use tempfile::tempdir;

use crate::report::Finding;

// Function to write findings to a JUnit XML file
pub fn write_junit(findings: &[Finding], writer: &mut impl Write) -> Result<(), quick_xml::Error> {
    let mut xml_writer = Writer::new_with_indent(writer, b' ', 4);

    // Write XML declaration
    xml_writer.write_event(Event::Decl(BytesDecl::new(b"1.0", Some(b"UTF-8"), None)))?;

    // Start "testsuites" element
    let mut testsuites_start = BytesStart::owned_name(b"testsuites");
    xml_writer.write_event(Event::Start(testsuites_start))?;

    // Write "testsuite" element
    let mut testsuite_start = BytesStart::owned_name(b"testsuite");
    testsuite_start.push_attribute(("failures", findings.len().to_string().as_str()));
    testsuite_start.push_attribute(("name", "keyshade secret-detect"));
    testsuite_start.push_attribute(("tests", findings.len().to_string().as_str()));
    xml_writer.write_event(Event::Start(testsuite_start))?;

    // Write "testcase" elements for each finding
    for finding in findings {
        let mut testcase_start = BytesStart::owned_name(b"testcase");
        testcase_start.push_attribute(("classname", &finding.description));
        testcase_start.push_attribute(("file", &finding.file));
        testcase_start.push_attribute(("name", &get_message(finding)));
        xml_writer.write_event(Event::Start(testcase_start))?;

        // Write "failure" element within "testcase"
        let mut failure_start = BytesStart::owned_name(b"failure");
        failure_start.push_attribute(("message", &get_message(finding)));
        failure_start.push_attribute(("type", &finding.description));
        xml_writer.write_event(Event::Start(failure_start))?;

        // Write finding data as CDATA within "failure"
        let data = to_string_pretty(finding).unwrap();
        xml_writer.write_event(Event::CData(data.into()))?;

        // Close "failure" element
        xml_writer.write_event(Event::End(BytesEnd::borrowed(b"failure")))?;

        // Close "testcase" element
        xml_writer.write_event(Event::End(BytesEnd::borrowed(b"testcase")))?;
    }

    // Close "testsuite" element
    xml_writer.write_event(Event::End(BytesEnd::borrowed(b"testsuite")))?;

    // Close "testsuites" element
    xml_writer.write_event(Event::End(BytesEnd::borrowed(b"testsuites")))?;

    Ok(())
}

// Helper function to generate the message for a finding
fn get_message(finding: &Finding) -> String {
    if finding.commit.is_empty() {
        format!(
            "{} has detected a secret in file {}, line {}.",
            finding.rule_id, finding.file, finding.start_line
        )
    } else {
        format!(
            "{} has detected a secret in file {}, line {}, at commit {}.",
            finding.rule_id, finding.file, finding.start_line, finding.commit
        )
    }
}

#[test]
fn test_write_junit() {
    let tests = vec![
        (
            "simple",
            vec![
                Finding {
                    description: "Test Rule".to_string(),
                    rule_id: "test-rule".to_string(),
                    match_str: "line containing secret".to_string(),
                    secret: "a secret".to_string(),
                    start_line: 1,
                    end_line: 2,
                    start_column: 1,
                    end_column: 2,
                    message: "opps".to_string(),
                    file: "auth.py".to_string(),
                    commit: "0000000000000000".to_string(),
                    author: "John Doe".to_string(),
                    email: "johndoe@gmail.com".to_string(),
                    date: "10-19-2003".to_string(),
                    tags: vec![],
                    ..Default::default()
                },
                Finding {
                    description: "Test Rule".to_string(),
                    rule_id: "test-rule".to_string(),
                    match_str: "line containing secret".to_string(),
                    secret: "a secret".to_string(),
                    start_line: 2,
                    end_line: 3,
                    start_column: 1,
                    end_column: 2,
                    message: "".to_string(),
                    file: "auth.py".to_string(),
                    commit: "".to_string(),
                    author: "".to_string(),
                    email: "".to_string(),
                    date: "".to_string(),
                    tags: vec![],
                    ..Default::default()
                },
            ],
            "tests/fixtures/junit_simple.xml",
            false,
        ),
        ("empty", vec![], "tests/fixtures/junit_empty.xml", false),
    ];

    for (test_name, findings, expected_path, want_empty) in tests {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(format!("{}.xml", test_name));
        let mut file = File::create(&file_path).unwrap();

        let result = write_junit(&findings, &mut file);
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