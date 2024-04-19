use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Project {
    pub api_key: String,
    pub private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Workspace {
    #[serde(flatten)]
    pub projects: Option<HashMap<String, Project>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Configure {
    pub base_url: String,
    #[serde(flatten)]
    pub workspaces: HashMap<String, Workspace>,
}
