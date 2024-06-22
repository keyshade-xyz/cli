use std::fmt;

// Structure to represent a finding
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub description: String,
    pub start_line: usize,
    pub end_line: usize,
    pub start_column: usize,
    pub end_column: usize,
    pub line: String,
    pub match_str: String,
    pub secret: String,
    pub file: String,
    pub symlink_file: String,
    pub commit: String,
    pub entropy: f32,
    pub author: String,
    pub email: String,
    pub date: String,
    pub message: String,
    pub tags: Vec<String>,
    pub rule_id: String,
    pub fingerprint: String,
}

impl Finding {
    // Method to redact sensitive information from a finding
    pub fn redact(&mut self, percent: u32) {
        let secret = mask_secret(&self.secret, percent);
        let redacted_secret = if percent >= 100 {
            "REDACTED".to_string()
        } else {
            secret
        };

        self.line = self.line.replace(&self.secret, &redacted_secret);
        self.match_str = self.match_str.replace(&self.secret, &redacted_secret);
        self.secret = redacted_secret;
    }
}

// Function to mask a secret based on redaction percentage
fn mask_secret(secret: &str, percent: u32) -> String {
    let percent = percent.min(100);
    let length = secret.len() as f64;
    if length <= 0.0 {
        return secret.to_string();
    }

    let prc = (100 - percent) as f64;
    let lth = (length * prc / 100.0).round() as usize;

    format!("{}
...", &secret[..lth])
}

#[test]
fn test_redact() {
    let tests = vec![
        (
            true,
            vec![Finding {
                match_str: "line containing secret".to_string(),
                secret: "secret".to_string(),
                ..Default::default()
            }],
        ),
    ];

    for (redact, findings) in tests {
        for mut finding in findings {
            if redact {
                finding.redact(100);
                assert_eq!("REDACTED", finding.secret);
                assert_eq!("line containing REDACTED", finding.match_str);
            }
        }
    }
}

#[test]
fn test_mask() {
    let tests = vec![
        (
            "normal secret",
            Finding {
                match_str: "line containing secret".to_string(),
                secret: "secret".to_string(),
                ..Default::default()
            },
            75,
            Finding {
                match_str: "line containing se...".to_string(),
                secret: "se...".to_string(),
                ..Default::default()
            },
        ),
        (
            "empty secret",
            Finding {
                match_str: "line containing".to_string(),
                secret: "".to_string(),
                ..Default::default()
            },
            75,
            Finding {
                match_str: "line containing".to_string(),
                secret: "".to_string(),
                ..Default::default()
            },
        ),
        (
            "short secret",
            Finding {
                match_str: "line containing".to_string(),
                secret: "ss".to_string(),
                ..Default::default()
            },
            75,
            Finding {
                match_str: "line containing".to_string(),
                secret: "...".to_string(),
                ..Default::default()
            },
        ),
    ];

    for (name, mut finding, percent, expected) in tests {
        finding.redact(percent);
        assert_eq!(
            expected, finding,
            "Test case '{}' failed. Expected: {:?}, Got: {:?}",
            name, expected, finding
        );
    }
}

#[test]
fn test_mask_secret() {
    let tests = vec![
        ("normal masking", "secret", 75, "se..."),
        ("high masking", "secret", 90, "s..."),
        ("low masking", "secret", 10, "secre..."),
        ("invalid masking", "secret", 1000, "..."),
    ];

    for (name, secret, percent, expected) in tests {
        let got = Finding::mask_secret(secret, percent);
        assert_eq!(
            expected, got,
            "Test case '{}' failed. Expected: {}, Got: {}",
            name, expected, got
        );
    }
}