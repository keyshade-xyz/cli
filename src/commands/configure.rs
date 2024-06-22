use clap::ArgMatches;
use std::io;
use std::io::Write;

use crate::{
    file_exists, generate_project_toml, generate_user_root_toml,
    get_os_specific_user_root_config_path, read_from_terminal, read_securely_from_terminal,
    write_file,
};

use super::AbstractCommandInterface;

#[derive(Debug)]
struct ConfigureCommandParsedData {
    workspace: String,
    project: String,
    environment: String,
    api_key: String,
    private_key: String,
}

pub struct ConfigureCommand<'a> {
    parsed_data: ConfigureCommandParsedData,
    args: &'a ArgMatches,
}

impl<'a> ConfigureCommand<'a> {
    pub fn new(args: &'a ArgMatches) -> ConfigureCommand<'a> {
        ConfigureCommand {
            parsed_data: ConfigureCommandParsedData {
                workspace: String::new(),
                project: String::new(),
                environment: String::new(),
                api_key: String::new(),
                private_key: String::new(),
            },
            args,
        }
    }

    fn create_keyshade_toml(&self) -> Result<(), io::Error> {
        println!("Creating keyshade.toml...");

        // Get the parsed toml content
        let toml_content = generate_project_toml!(
            self.parsed_data.workspace,
            self.parsed_data.project,
            self.parsed_data.environment
        );

        // Write the toml content to the file
        write_file!("keyshade.toml", toml_content);

        println!("keyshade.toml created successfully!");

        Ok(())
    }

    fn create_user_root_toml(&self) -> Result<(), io::Error> {
        println!("Creating user root toml...");

        // Get the user root toml path
        let user_root_toml_path = get_os_specific_user_root_config_path!(self.parsed_data.project);

        // Get the parsed toml content
        let toml_content = generate_user_root_toml!(
            self.parsed_data.api_key,
            self.parsed_data.private_key,
            self.parsed_data.project
        );

        // Write the toml content to the file
        write_file!(&user_root_toml_path, toml_content);

        println!("User root toml created successfully!");

        Ok(())
    }
}

impl<'a> AbstractCommandInterface for ConfigureCommand<'a> {
    fn parse_args(&mut self) -> Result<(), io::Error> {
        let args = self.args;

        let workspace = if let Some(w) = args.get_one::<String>("WORKSPACE") {
            w.to_string()
        } else {
            read_from_terminal!("Enter the workspace name: ")
        };

        // Read project name
        let project = if let Some(p) = args.get_one::<String>("PROJECT") {
            p.to_string()
        } else {
            read_from_terminal!("Enter the project name:")
        };

        // Read environment name
        let environment = if let Some(e) = args.get_one::<String>("ENVIRONMENT") {
            e.to_string()
        } else {
            read_from_terminal!("Enter the environment name: ")
        };

        // Read API Key
        let api_key = if let Some(a) = args.get_one::<String>("API_KEY") {
            a.to_string()
        } else {
            read_securely_from_terminal!("Enter your API Key:")
        };

        // Read Private Key
        let private_key = if let Some(p) = args.get_one::<String>("PRIVATE_KEY") {
            p.to_string()
        } else {
            read_securely_from_terminal!("Enter your Private Key:")
        };

        self.parsed_data = ConfigureCommandParsedData {
            workspace,
            project,
            environment,
            api_key,
            private_key,
        };

        Ok(())
    }

    fn execute(&self) -> Result<(), io::Error> {
        let mut should_upsert_keyshade_toml = true;
        let mut should_upsert_user_root_toml = true;

        // Check if keyshade.toml exists in the current directory
        if file_exists!("keyshade.toml") {
            // If it does, ask if the users want to overwrite it
            let choice = read_from_terminal!(
                "keyshade.toml already exists. Do you want to overwrite it? (y/n): "
            );

            if choice.to_lowercase() != "y" {
                println!("Skipping keyshade.toml creation...");
                should_upsert_keyshade_toml = false;
            }
        }

        // Check if user root toml exists
        let user_root_toml_path = get_os_specific_user_root_config_path!(self.parsed_data.project);
        if file_exists!(&user_root_toml_path) {
            // If it does, ask if the users want to overwrite it
            let choice = read_from_terminal!(format!(
                "{} already exists. Do you want to overwrite it? (y/n): ",
                user_root_toml_path
            ));

            if choice.to_lowercase() != "y" {
                println!("Skipping user root toml creation...");
                should_upsert_user_root_toml = false;
            }
        }

        if should_upsert_keyshade_toml {
            self.create_keyshade_toml()?;
        }

        if should_upsert_user_root_toml {
            self.create_user_root_toml()?;
        }
        Ok(())
    }
}
