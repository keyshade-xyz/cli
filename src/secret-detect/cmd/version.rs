use clap::{ArgMatches, Command};

// Version string, to be set by the build process
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Function to run the version command
pub fn run_version(_matches: &ArgMatches) {
    println!("{}", VERSION);
}

// Function to create the version subcommand
pub fn build_version_command() -> Command<'static> {
    Command::new("version")
        .about("display keyshade secret scanner version")
}