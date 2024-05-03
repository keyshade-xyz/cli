use regex::Regex;

#[derive(Debug)]
pub struct Rule {
    pub description: String,
    pub rule_id: String,
    pub entropy: f64,
    pub secret_group: u32,
    pub regex: Option<Regex>,
    pub path: Option<Regex>,
    pub tags: Vec<String>,
    pub keywords: Vec<String>,
    pub allowlist: Allowlist,
}
