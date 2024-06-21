use clap::ArgMatches;
use std::io;

use crate::util::{read_from_terminal, read_securely_from_terminal};

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
}

impl<'a> AbstractCommandInterface for ConfigureCommand<'a> {
    fn parse_args(&mut self) -> Result<(), io::Error> {
        let args = self.args;

        let workspace = if let Some(w) = args.get_one::<String>("WORKSPACE") {
            w.to_string()
        } else {
            read_from_terminal("Enter the workspace name: ")?
        };

        // Read project name
        let project = if let Some(p) = args.get_one::<String>("PROJECT") {
            p.to_string()
        } else {
            read_from_terminal("Enter the project name: ")?
        };

        // Read environment name
        let environment = if let Some(e) = args.get_one::<String>("ENVIRONMENT") {
            e.to_string()
        } else {
            read_from_terminal("Enter the environment name: ")?
        };

        // Read API Key
        let api_key = if let Some(a) = args.get_one::<String>("API_KEY") {
            a.to_string()
        } else {
            read_securely_from_terminal("Enter your API Key:")?
        };

        // Read Private Key
        let private_key = if let Some(p) = args.get_one::<String>("PRIVATE_KEY") {
            p.to_string()
        } else {
            read_securely_from_terminal("Enter your Private Key:")?
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
        println!("{:?}\n", self.parsed_data);
        Ok(())
    }
}
