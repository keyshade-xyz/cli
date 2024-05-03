use regex::Regex;
use std::collections::HashSet;

pub struct Allowlist {
    pub description: String,
    pub regexes: Vec<Regex>,
    pub regex_target: Option<String>,
    pub paths: Vec<Regex>,
    pub commits: HashSet<String>,
    pub stop_words: HashSet<String>,
}

impl Allowlist {
    pub fn commit_allowed(&self, c: &str) -> bool {
        self.commits.contains(c)
    }

    pub fn path_allowed(&self, path: &str) -> bool {
        self.paths.iter().any(|r| r.is_match(path))
    }

    pub fn regex_allowed(&self, s: &str) -> bool {
        match &self.regex_target {
            Some(target) => self.regexes.iter().any(|r| r.is_match(s) && r.is_match(target)),
            None => self.regexes.iter().any(|r| r.is_match(s)),
        }
    }

    pub fn contains_stop_word(&self, s: &str) -> bool {
        let s_lower = s.to_lowercase();
        self.stop_words.iter().any(|stop_word| s_lower.contains(stop_word))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_allowed() {
        let tests = [
            (
                Allowlist {
                    commits: vec!["commitA".to_string()],
                },
                "commitA",
                true,
            ),
            (
                Allowlist {
                    commits: vec!["commitB".to_string()],
                },
                "commitA",
                false,
            ),
            (
                Allowlist {
                    commits: vec!["commitB".to_string()],
                },
                "",
                false,
            ),
        ];

        for (allowlist, commit, expected) in tests {
            assert_eq!(allowlist.commit_allowed(commit), expected);
        }
    }

    #[test]
    fn regex_allowed() {
        let tests = [
            (
                Allowlist {
                    regexes: vec![Regex::new("matchthis").unwrap()],
                },
                "a secret: matchthis, done",
                true,
            ),
            (
                Allowlist {
                    regexes: vec![Regex::new("matchthis").unwrap()],
                },
                "a secret",
                false,
            ),
        ];

        for (allowlist, secret, expected) in tests {
            assert_eq!(allowlist.regex_allowed(secret), expected);
        }
    }

    #[test]
    fn path_allowed() {
        let tests = [
            (
                Allowlist {
                    paths: vec![Regex::new("path").unwrap()],
                },
                "a path",
                true,
            ),
            (
                Allowlist {
                    paths: vec![Regex::new("path").unwrap()],
                },
                "a ???",
                false,
            ),
        ];

        for (allowlist, path, expected) in tests {
            assert_eq!(allowlist.path_allowed(path), expected);
        }
    }
}
