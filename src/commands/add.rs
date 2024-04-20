use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use colored::Colorize;
use directories::UserDirs;
use inquire::Password;
use spinners::{Spinner, Spinners};
use std::io::Write;

use crate::{constants::CONFIG_FILE_NAME, generate_workspace_toml};
/// Adds a new workspace and project to the keyshades-cli configuration file.
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
/// add(&workspace, project.as_ref());
/// ```
pub fn add(wrkspc: &String, prjct: Option<&String>) {
    let mut api_key_input: String = String::new();
    let mut private_key_input: String = String::new();

    if let Some(user_dirs) = UserDirs::new() {
        let config_dir: &Path = user_dirs.home_dir();
        let config_file_path = config_dir.join(CONFIG_FILE_NAME);
        match fs::read_to_string(config_file_path.clone()) {
            Ok(_config_file) => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(config_file_path.clone())
                    .unwrap();
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
                    let config_str: String = generate_workspace_toml!(
                        wrkspc,
                        Some(project.to_string()),
                        api_key_input,
                        private_key_input
                    );
                    // fs::write(config_dir.join(CONFIG_FILE_NAME), config_str).unwrap();
                    if let Err(e) = writeln!(file, "{}", config_str) {
                        eprintln!("Couldn't write to file: {}", e);
                    }
                } else {
                    let config_str: String = generate_workspace_toml!(wrkspc, None, "", "");
                    // fs::write(config_dir.join(CONFIG_FILE_NAME), config_str).unwrap();
                    if let Err(e) = writeln!(file, "{}", config_str) {
                        eprintln!("Couldn't write to file: {}", e);
                    }
                }

                sp.stop();
                println!("\n{}", "Config file created 🎉".bright_green());
            }
            Err(_e) => {
                println!("{}", "Config file does not exist".bright_yellow().bold());
                println!(
                    "{}",
                    "Please run the configure command first".bright_yellow()
                );
                println!("{}", "Usage: ks configure -h".bright_yellow());
            }
        }
    } else {
        eprintln!(
            "{}",
            "Error: Could not find the user's home directory".bright_red()
        );
    }
}
