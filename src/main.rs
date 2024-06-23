mod commands;
mod constants;
mod macros;
mod models;

use std::io;

use crate::constants::{ABOUT, VERSION};
use clap::{Arg, ArgAction, ArgMatches, Command};

use commands::{configure::ConfigureCommand, run::RunCommand, AbstractCommandInterface};

fn cli() -> Command {
    Command::new("keyshades-cli")
        .alias("ks")
        .version(VERSION)
        .about(ABOUT)
        .max_term_width(100)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("configure")
                .alias("conf")
                .about("Configure the keyshades CLI, alias to `conf`")
                .arg(
                    Arg::new("WORKSPACE")
                        .long("workspace")
                        .short('w')
                        .action(ArgAction::Set)
                        .help("Configure the workspace"),
                )
                .arg(
                    Arg::new("PROJECT")
                        .long("project")
                        .short('p')
                        .action(ArgAction::Set)
                        .help("Configure the project"),
                )
                .arg(
                    Arg::new("ENVIRONMENT")
                        .long("environment")
                        .short('e')
                        .action(ArgAction::Set)
                        .help("Configure the environment"),
                )
                .arg(
                    Arg::new("API_KEY")
                        .long("api-key")
                        .short('a')
                        .action(ArgAction::Set)
                        .help("Configure the API key"),
                )
                .arg(
                    Arg::new("PRIVATE_KEY")
                        .long("private-key")
                        .short('k')
                        .action(ArgAction::Set)
                        .help("Configure the private key"),
                ),
        )
        .subcommand(
            Command::new("run")
                .alias("r")
                .about("Run the keyshades CLI, alias to `r`"),
        )
}

pub enum CommandEnum<'a> {
    Configure(ConfigureCommand<'a>),
    Run(RunCommand),
}

impl<'a> AbstractCommandInterface for CommandEnum<'a> {
    fn parse_args(&mut self) -> Result<(), io::Error> {
        match self {
            CommandEnum::Configure(command) => command.parse_args(),
            CommandEnum::Run(command) => command.parse_args(),
        }
    }

    async fn execute(&self) -> Result<(), io::Error> {
        match self {
            CommandEnum::Configure(command) => command.execute().await,
            CommandEnum::Run(command) => command.execute().await,
        }
    }
}

#[tokio::main]
async fn main() {
    let matches: ArgMatches = cli().get_matches();
    let mut command: Option<CommandEnum> = None;

    // Get the subcommand implementation based on the user input
    match matches.subcommand() {
        Some(("configure", args)) => {
            command = Some(CommandEnum::Configure(ConfigureCommand::new(args)));
        }
        Some(("run", _args)) => {
            command = Some(CommandEnum::Run(RunCommand::new()));
        }
        _ => {
            println!("Error: No subcommand provided. Usage: ks [SUBCOMMAND] [OPTIONS]");
        }
    }

    // Execute the subcommand
    if let Some(mut c) = command {
        c.parse_args().unwrap();
        let _ = c.execute().await;
    } else {
        panic!("Error: No subcommand provided. Usage: ks [SUBCOMMAND] [OPTIONS]");
    }
}
