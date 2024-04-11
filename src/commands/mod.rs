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
                .alias("config")
                .about("Configure the keyshades CLI, alias to `config`")
                .arg(arg!(-w --workspace <WORKSPACE> "Configure the workspace"))
                .arg(arg!(-p --project <PROJECT> "Configure the project")),
        )
        .subcommand(Command::new(""))
}
/// Execute the command line application
pub fn main() {
    let matches = cli().get_matches();
    print!("{:?}", matches)
}
