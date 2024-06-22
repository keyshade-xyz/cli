use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRootConfig {
    pub api_key: String,
    pub private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectRootConfig {
    pub workspace: String,
    pub project: String,
    pub environment: String,
}
