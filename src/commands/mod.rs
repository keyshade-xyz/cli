use crate::constants::{ABOUT, VERSION};
use clap::{arg, Command};

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
                .arg(arg!(-w --workspace <WORKSPACE> "Configure the workspace"))
                .arg(arg!(-p --project <PROJECT> "Configure the project")),
        )
        .subcommand(
            Command::new("add")
                .about("Add a new project to the workspace or a new workspace")
                .arg(arg!(-w --workspace <WORKSPACE> "Add the workspace").required(true))
                .arg(arg!(-p --project <PROJECT> "Add the project, to add a project you must specify the workspace")),
        ).subcommand(
            Command::new("remove")
                .alias("rm")
                .about("Remove project(s) or workspace(s), alias to `rm`")
                .arg(arg!(-w --workspace <WORKSPACE> "Configure the workspace ").required(true))
                .arg(arg!(-p --project <PROJECT> "Configure the project")),
        ).subcommand(
            Command::new("list")
                .alias("li")
                .about("Add project(s) or workspace(s), alias to `li`")
                .arg(arg!(-w --workspace <WORKSPACE> "list all workspace").required(true))
                .arg(arg!(-p --project <PROJECT> "list all projects")),
        )
}
/// Execute the command line application
pub fn main() {
    let matches = cli().get_matches();
    print!("{:?}", matches)
}
