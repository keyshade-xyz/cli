use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[derive(Debug, Deserialize, Serialize)]
pub struct ViperConfig {
    description: String,
    extend: Extend,
    rules: Vec<Rule>,
    allowlist: Allowlist,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Extend {
    path: Option<String>,
    url: Option<String>,
    use_default: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    description: String,
    rule_id: String,
    regex: Option<Regex>,
    path: Option<Regex>,
    secret_group: u32,
    entropy: f64,
    tags: Vec<String>,
    keywords: Vec<String>,
    allowlist: Allowlist,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Allowlist {
    regex_target: Option<String>,
    regexes: Vec<Regex>,
    paths: Vec<Regex>,
    commits: Vec<String>,
    stop_words: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    extend: Extend,
    path: String,
    description: String,
    rules: HashMap<String, Rule>,
    allowlist: Allowlist,
    keywords: Vec<String>,
    ordered_rules: Vec<String>,
}

impl Config {
    fn translate(viper_config: ViperConfig) -> Result<Self, String> {
        let mut keywords = Vec::new();
        let mut ordered_rules = Vec::new();
        let mut rules_map = HashMap::new();

        for rule in viper_config.rules {
            let allowlist_regexes = rule.allowlist.regexes.iter().map(|r| Regex::new(r.as_str())?)
                .collect::<Result<Vec<_>, _>>()?;
            let allowlist_paths = rule.allowlist.paths.iter().map(|r| Regex::new(r.as_str())?)
                .collect::<Result<Vec<_>, _>>()?;

            let mut rule_keywords = rule.keywords.iter().map(|k| k.to_lowercase()).collect();
            keywords.append(&mut rule_keywords);

            let config_regex = rule.regex.as_ref().map(|r| Regex::new(r.as_str())?);
            let config_path_regex = rule.path.as_ref().map(|r| Regex::new(r.as_str())?);

            let allowlist = Allowlist {
                regex_target: rule.allowlist.regex_target,
                regexes: allowlist_regexes,
                paths: allowlist_paths,
                commits: rule.allowlist.commits,
                stop_words: rule.allowlist.stop_words,
            };

            if rule.regex.is_some() && rule.secret_group > rule.regex.unwrap().captures_len() {
                return Err(format!(
                    "Invalid regex secret group {} for rule {}, max is {}",
                    rule.secret_group, rule.description, rule.regex.unwrap().captures_len()
                ));
            }

            rules_map.insert(rule.rule_id.clone(), Rule {
                description: rule.description,
                rule_id: rule.rule_id,
                regex: config_regex,
                path: config_path_regex,
                secret_group: rule.secret_group,
                entropy: rule.entropy,
                tags: rule.tags,
                keywords: rule_keywords,
                allowlist,
            });
            ordered_rules.push(rule.rule_id);
        }

        let allowlist_regexes = viper_config.allowlist.regexes.iter().map(|r| Regex::new(r.as_str())?)
            .collect::<Result<Vec<_>, _>>()?;
        let allowlist_paths = viper_config.allowlist.paths.iter().map(|r| Regex::new(r.as_str())?)
            .collect::<Result<Vec<_>, _>>()?;

        let mut config = Config {
            extend: viper_config.extend,
            path: String::new(), // Set later
            description: viper_config.description,
            rules: rules_map,
            allowlist: Allowlist {
                regex_target: viper_config.allowlist.regex_target,
                regexes: allowlist_regexes,
                paths: allowlist_paths,
                commits: viper_config.allowlist.commits,
                stop_words: viper_config.allowlist.stop_words,
            },
            keywords,
            ordered_rules,
        };

        if extend_depth != max_extend_depth {
            if config.extend.path.is_some() && config.extend.use_default {
                return Err("Using both extend.path and extend.useDefault is not allowed".to_string());
            }

            if config.extend.use_default {
                config.extend_default()?;
            } else if let Some(path) = &config.extend.path {
                config.extend_path(path)?;
            }
        }

        Ok(config)
    }

    fn get_ordered_rules(&self) -> Vec<&Rule> {
        self.ordered_rules.iter().filter_map(|id| self.rules.get(id)).collect()
    }

    fn extend_default(&mut self) -> Result<(), String> {
        extend_depth += 1;
        // Use serde to deserialize the embedded config
        let default_config: Result<ViperConfig, serde_json::Error> =
            serde_json::from_str(&DefaultConfig);

        match default_config {
            Ok(viper_config) => {
                let extension_config = Config::translate(viper_config)?;
                log::debug!("Extending config with default config");
                self.extend(extension_config);
                Ok(())
            }
            Err(err) => Err(format!("Failed to load extended config: {}", err)),
        }
    }

    fn extend_path(&mut self, path: &str) -> Result<(), String> {
        extend_depth += 1;
        // Use serde to deserialize the config file
        let extension_config: Result<ViperConfig, serde_json::Error> =
            serde_json::from_str(&std::fs::read_to_string(path)?);

        match extension_config {
            Ok(viper_config) => {
                let extension_config = Config::translate(viper_config)?;
                log::debug!("Extending config with {}", path);
                self.extend(extension_config);
                Ok(())
            }
            Err(err) => Err(format!("Failed to load extended config: {}", err)),
        }
    }

    fn extend(&mut self, extension_config: Config) {
        for (rule_id, rule) in extension_config.rules {
            if !self.rules.contains_key(&rule_id) {
                log::trace!("Adding {} to base config", rule_id);
                self.rules.insert(rule_id.clone(), rule);
                self.keywords.extend(rule.keywords.iter().cloned());
                self.ordered_rules.push(rule_id);
            }
        }

        // Append allowlists without merging
        self.allowlist.commits.extend(extension_config.allowlist.commits.iter().cloned());
        self.allowlist.paths.extend(extension_config.allowlist.paths.iter().cloned());
        self.allowlist.regexes.extend(extension_config.allowlist.regexes.iter().cloned());

        // Sort ordered rules for consistency
        self.ordered_rules.sort();
    }
}

#[derive(Debug)]
struct ConfigError {
    message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for ConfigError {}

// Structure representing a rule
struct Rule {
    description: String,
    regex: Regex,
    tags: Vec<String>,
    keywords: Vec<String>,
    rule_id: String,
    allowlist: Allowlist,
    entropy: Option<f64>,
    secret_group: Option<u8>,
}

// Structure representing an allowlist
struct Allowlist {
    regexes: Vec<Regex>,
    commits: Vec<String>,
    paths: Vec<Regex>,
}

// Structure representing the configuration
struct Config {
    rules: HashMap<String, Rule>,
}

// Function to convert Viper configuration to Rust configuration
fn translate(viper_config: &ViperConfig) -> Result<Config, ConfigError> {
    let mut rules = HashMap::new();
    for (rule_id, rule_data) in &viper_config.rules {
        let regex = Regex::new(&rule_data.regex).map_err(|e| ConfigError {
            message: format!("Invalid regex for rule '{}': {}", rule_id, e),
        })?;

        let allowlist = Allowlist {
            regexes: rule_data
                .allowlist
                .regexes
                .iter()
                .map(|r| Regex::new(r).unwrap())
                .collect(),
            commits: rule_data.allowlist.commits.clone(),
            paths: rule_data
                .allowlist
                .paths
                .iter()
                .map(|r| Regex::new(r).unwrap())
                .collect(),
        };

        // Validate secret group
        if let Some(group) = rule_data.secret_group {
            if group > 3 {
                return Err(ConfigError {
                    message: format!(
                        "{} invalid regex secret group {}, max regex secret group 3",
                        rule_data.description, group
                    ),
                });
            }
        }

        rules.insert(
            rule_id.to_string(),
            Rule {
                description: rule_data.description.clone(),
                regex,
                tags: rule_data.tags.clone(),
                keywords: rule_data.keywords.clone(),
                rule_id: rule_id.to_string(),
                allowlist,
                entropy: rule_data.entropy,
                secret_group: rule_data.secret_group,
            },
        );
    }

    Ok(Config { rules })
}
