use colored::Colorize;
use inquire::Password;
use spinners::{Spinner, Spinners};
use std::{fs, path::Path};

use directories::UserDirs;

use crate::{constants::CONFIG_FILE_NAME, generate_config_toml};

/// Configures the keyshades-cli by creating a configuration file in the user's home directory.
///
/// # Arguments
///
/// * `wrkspc` - A reference to a `String` representing the workspace name.
/// * `prjct` - An optional reference to a `String` representing the project name.
///
/// # Example
///
/// ```
/// let workspace = "my_workspace".to_string();
/// let project = Some("my_project".to_string());
/// configure(&workspace, project.as_ref());
/// ```
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

                let mut sp = Spinner::new(Spinners::Dots9, "Creating config file...".into());
                if let Some(project) = prjct {
                    let config_str: String = generate_config_toml!(
                        wrkspc,
                        Some(project.to_string()),
                        api_key_input,
                        private_key_input
                    );
                    fs::write(config_dir.join(CONFIG_FILE_NAME), config_str).unwrap();
                } else {
                    let config_str: String = generate_config_toml!(wrkspc, None, "", "");
                    fs::write(config_dir.join(CONFIG_FILE_NAME), config_str).unwrap();
                }

                sp.stop();
                println!("\n{}", "Config file created 🎉".bright_green());
            }
        }
    } else {
        eprintln!(
            "{}",
            "Error: Could not find the user's home directory".bright_red()
        );
    }
}
