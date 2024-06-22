use std::fs::{self, File};
use std::io::Write;

use serde::Serialize;
use serde_json::{json, to_writer_pretty};
use tempfile::tempdir;

use crate::config::{Config, Rule};
use crate::report::Finding;

// Constants for SARIF report
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const VERSION: &str = "1.0.0";
const DRIVER: &str = "keyshade secret-detect";

// Structs representing the SARIF report structure
#[derive(Serialize)]
pub struct Sarif {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec
}

#[derive(Serialize, Clone, Default)]
pub struct Runs {
    pub tool: Tool,
    pub results: Vec<Results>,
}

#[derive(Serialize, Clone, Default)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Serialize, Clone, Default)]
pub struct Driver {
    pub name: String,
    pub semantic_version: String,
    pub information_uri: String,
    pub rules: Vec<Rules>,
}

#[derive(Serialize, Clone, Default)]
pub struct Rules {
    pub id: String,
    pub name: String,
    pub short_description: ShortDescription,
    pub full_description: Option<FullDescription>,
}

#[derive(Serialize, Clone, Default)]
pub struct ShortDescription {
    pub text: String,
}

#[derive(Serialize, Clone, Default)]
pub struct FullDescription {
    pub text: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Message {
    pub text: String,
}

#[derive(Serialize, Clone, Default)]
pub struct ArtifactLocation {
    pub uri: String,
    pub uri_base_id: Option<String>,
    pub index: Option<u64>,
}

#[derive(Serialize, Clone, Default)]
pub struct Region {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub char_offset: Option<u64>,
    pub char_length: Option<u64>,
    pub byte_offset: Option<u64>,
    pub byte_length: Option<u64>,
    pub snippet: Snippet,
}

#[derive(Serialize, Clone, Default)]
pub struct Snippet {
    pub text: String,
}

#[derive(Serialize, Clone, Default)]
pub struct PhysicalLocation {
    pub artifact_location: ArtifactLocation,
    pub region: Region,
    pub context_region: Option<Region>,
}

#[derive(Serialize, Clone, Default)]
pub struct Locations {
    pub physical_location: PhysicalLocation,
    pub logical_locations: Option<Vec<LogicalLocations>>,
    pub message: Option<Message>,
    pub annotations: Option<Vec<Annotation>>,
}

#[derive(Serialize, Clone, Default)]
pub struct LogicalLocations {
    pub kind: Option<String>,
    pub name: Option<String>,
    pub fully_qualified_name: Option<String>,
    pub decorated_name: Option<String>,
    pub index: Option<u64>,
    pub parent_index: Option<u64>,
}

#[derive(Serialize, Clone, Default)]
pub struct Annotation {
    pub location: Option<Locations>,
    pub message: Message,
    pub properties: Option<Properties>,
}

#[derive(Serialize, Clone, Default)]
pub struct PartialFingerprints {
    pub commit_sha: String,
    pub email: String,
    pub author: String,
    pub date: String,
    pub commit_message: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Properties {
    pub tags: Vec<String>,
    #[serde(flatten)]
    pub additional_properties: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Clone, Default)]
pub struct Results {
    pub rule_id: String,
    pub rule_index: Option<u64>,
    pub message: Message,
    pub locations: Vec<Locations>,
    pub partial_fingerprints: PartialFingerprints,
    pub properties: Properties,
    pub taxa: Option<Vec<Taxa>>,
}

#[derive(Serialize, Clone, Default)]
pub struct Taxa {
    pub tool_component: ToolComponent,
}

#[derive(Serialize, Clone, Default)]
pub struct ToolComponent {
    pub name: String,
    pub index: Option<u64>,
    pub guid: Option<String>,
    pub properties: Option<Properties>,
}


// Function to write findings to a SARIF JSON file
pub fn write_sarif(
    config: &Config,
    findings: &[Finding],
    writer: &mut impl Write,
) -> Result<(), serde_json::Error> {
    // Build SARIF report structure
    let sarif_report = Sarif {
        schema: SCHEMA.to_string(),
        version: VERSION.to_string(),
        runs: vec![Runs {
            tool: Tool {
                driver: Driver {
                    name: DRIVER.to_string(),
                    semantic_version: env!("CARGO_PKG_VERSION").to_string(), // Get version from Cargo
                    information_uri: "https://github.com/zricethezav/gitleaks".to_string(),
                    rules: config.rules.values().cloned().map(get_rule).collect(),
                },
            },
            results: findings.iter().map(get_result).collect(),
        }],
    };

    // Write SARIF report to the writer
    to_writer_pretty(writer, &sarif_report)
}

// Helper function to convert a `Rule` to a `Rules` struct for SARIF
fn get_rule(rule: &Rule) -> Rules {
    Rules {
        id: rule.rule_id.clone(),
        name: rule.description.clone(),
        short_description: ShortDescription {
            text: rule
                .regex
                .as_ref()
                .map(|r| r.to_string())
                .unwrap_or_else(|| "Custom Rule".to_string()), // Placeholder for custom rules
        },
        full_description: None, // Not used in this example
    }
}

// Helper function to convert a `Finding` to a `Results` struct for SARIF
fn get_result(finding: &Finding) -> Results {
    Results {
        message: Message {
            text: get_message_text(finding),
        },
        rule_id: finding.rule_id.clone(),
        locations: vec![Locations {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: if !finding.symlink_file.is_empty() {
                        finding.symlink_file.clone()
                    } else {
                        finding.file.clone()
                    },
                    ..Default::default()
                },
                region: Region {
                    start_line: finding.start_line,
                    start_column: finding.start_column,
                    end_line: finding.end_line,
                    end_column: finding.end_column,
                    snippet: Snippet {
                        text: finding.secret.clone(),
                    },
                    ..Default::default()
                },
            },
            ..Default::default()
        }],
        partial_fingerprints: PartialFingerprints {
            commit_sha: finding.commit.clone(),
            email: finding.email.clone(),
            author: finding.author.clone(),
            date: finding.date.clone(),
            commit_message: finding.message.clone(),
        },
        properties: Properties {
            tags: finding.tags.clone(),
            ..Default::default()
        },
        ..Default::default()
    }
}

// Helper function to generate the message text for a SARIF result
fn get_message_text(finding: &Finding) -> String {
    if finding.commit.is_empty() {
        format!(
            "{} has detected secret for file {}.",
            finding.rule_id, finding.file
        )
    } else {
        format!(
            "{} has detected secret for file {} at commit {}.",
            finding.rule_id, finding.file, finding.commit
        )
    }
}


#[test]
fn test_write_sarif() {
    let tests = vec![(
        "simple",
        vec![Finding {
            description: "A test rule".to_string(),
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
            tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            ..Default::default()
        }],
        "tests/fixtures/sarif_simple.sarif",
        false,
    )];

    for (config_name, findings, expected_path, want_empty) in tests {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join(format!("{}.json", config_name));
        let mut file = File::create(&file_path).unwrap();

        // Load config
        let config = Config::load_from_file(&format!("tests/fixtures/{}.toml", config_name)).unwrap();

        let result = write_sarif(&config, &findings, &mut file);
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