use colored::Colorize;
use inquire::Password;
use serde::{Deserialize, Serialize};
use spinners::{Spinner, Spinners};
use std::{collections::HashMap, fs, path::Path};

use directories::UserDirs;

use crate::constants::{BASE_URL, CONFIG_FILE_NAME};

#[derive(Debug, Serialize, Deserialize)]
struct Project {
    api_key: String,
    private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Workspace {
    #[serde(flatten)]
    projects: Option<HashMap<String, Project>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Configure {
    base_url: String,
    #[serde(flatten)]
    workspaces: HashMap<String, Workspace>,
}

pub fn configure(wrkspc: &String, prjct: Option<&String>) {
    let mut api_key_input: String = String::new();
    let mut private_key_input: String = String::new();

    println!("\n{}\n", "* Configuring the keyshades-cli".on_cyan().bold());

    if let Some(user_dirs) = UserDirs::new() {
        let config_dir: &Path = user_dirs.home_dir();
        // Linux:   /home/JohnDoe
        // Windows: C:\Users\JohnDoe
        // macOS:   /Users/JohnDoe

        match fs::read_to_string(config_dir.join(CONFIG_FILE_NAME)) {
            Ok(_config_file) => {
                println!("{}", "Config file exists 🙌".bright_green());
            }
            Err(_e) => {
                // add a new workspace and project if the file does not exist

                if prjct.is_some() {
                    api_key_input = Password::new("Enter your API Key:")
                        .without_confirmation()
                        .prompt()
                        .unwrap();
                    private_key_input = Password::new("Enter your Private Key:")
                        .without_confirmation()
                        .prompt()
                        .unwrap();
                }

                let mut sp = Spinner::new(
                    Spinners::Dots9,
                    "Creating config file...".into(),
                );

                let mut workspace_map: HashMap<String, Workspace> = HashMap::new();
                workspace_map.insert(
                    wrkspc.to_string(),
                    Workspace {
                        projects: match prjct {
                            Some(project) => {
                                let mut project_map = HashMap::new();
                                project_map.insert(
                                    project.to_string(),
                                    Project {
                                        api_key: api_key_input.to_string(),
                                        private_key: private_key_input.to_string(),
                                    },
                                );
                                Some(project_map)
                            }
                            None => None,
                        },
                    },
                );

                let config: Configure = Configure {
                    base_url: BASE_URL.to_string(),
                    workspaces: workspace_map,
                };

                let config_str: String = toml::to_string(&config).unwrap();
                fs::write(config_dir.join(CONFIG_FILE_NAME), config_str).unwrap();
                // dbg!(config);
                // dbg!(config_str);
                sp.stop();
				println!("\n{}", "Config file created 🎉".bright_green());
            }
        }
        // let config: Configure = toml::from_str(
        //     r#"
        // 	base_url = "https://api.keyshades.com"

        // 	[keyshade]
        // 	[keyshade.backend]
        // 	api_key = "api_key"
        // 	private_key = "private key"
        // 	[keyshade.frontend]
        // 	api_key = "api_key 2"
        // 	private_key = "private key 2"

        // 	[truezk.ui]
        // 	api_key = "api_key 3"
        // 	private_key = "private key 3"

        //  "#,
        // )
        // .unwrap();

        // dbg!(config_dir);
    }
}
