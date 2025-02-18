/// The version of the application.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const ABOUT: &str = "A command line utility for keyshades.

This tools helps you to populate your secrects to your application, and manage them in a secure way.
Use `--help` on the subcommands to learn more about them.";

pub const CONFIG_FILE_NAME: &str = ".keyshade.toml";

pub const BASE_URL: &str = "https://api.keyshades.com";