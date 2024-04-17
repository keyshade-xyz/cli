use crate::{
    commands::configure::configure,
    constants::{ABOUT, VERSION},
};
mod configure;
use clap::{arg, Arg, ArgAction, ArgMatches, Command};

/// Constructs the command line interface for the keyshades CLI.
pub fn cli() -> Command {
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
                        .help("Configure the workspace")
                        .required(true),
                )
                .arg(
                    Arg::new("PROJECT")
                        .long("project")
                        .short('p')
                        .action(ArgAction::Set)
                        .help("Configure the project"),
                ),
        )
        .subcommand(
            Command::new("add")
                .about("Add a new project to the workspace or a new workspace")
                .arg(
                    Arg::new("WORKSPACE")
                        .long("workspace")
                        .short('w')
                        .action(ArgAction::Set)
                        .help("Add the workspace")
                        .required(true),
                )
                .arg(
                    Arg::new("PROJECT")
                        .long("project")
                        .short('p')
                        .action(ArgAction::Set)
                        .help("Add the project, to add a project you must specify the workspace"),
                ),
        )
        .subcommand(
            Command::new("remove")
                .alias("rm")
                .about("Remove project(s) or workspace(s), alias to `rm`")
                .arg(arg!(-w --workspace <WORKSPACE> "Configure the workspace ").required(true))
                .arg(arg!(-p --project <PROJECT> "Configure the project")),
        )
        .subcommand(
            Command::new("list")
                .alias("li")
                .about("Add project(s) or workspace(s), alias to `li`")
                .arg(arg!(-w --workspace <WORKSPACE> "list all workspace").required(true))
                .arg(arg!(-p --project <PROJECT> "list all projects")),
        )
}

pub fn execution() {
    let matches: ArgMatches = cli().get_matches();
    match matches.subcommand() {
        Some(("configure", sub_m)) => {
            let workspace: &String = sub_m.get_one::<String>("WORKSPACE").unwrap();
            let project: Option<&String> = sub_m.get_one::<String>("PROJECT");
            configure(workspace, project);
        }
        Some(("add", sub_m)) => {
            dbg!(sub_m);
        }
        Some(("remove", sub_m)) => {
            dbg!(sub_m);
        }
        Some(("list", sub_m)) => {
            dbg!(sub_m);
        }
        _ => {
            println!("No subcommand was used");
        }
    }
}

/// Executes the command line application.
pub fn main() {
    execution();
}
