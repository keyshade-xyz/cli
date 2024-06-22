use std::io;

use super::AbstractCommandInterface;

struct RunCommandParsedData {}

pub struct RunCommand<'a> {
    parsed_data: RunCommandParsedData,
    args: &'a clap::ArgMatches,
}

impl RunCommand<'_> {
    pub fn new(args: &clap::ArgMatches) -> RunCommand {
        RunCommand {
            parsed_data: RunCommandParsedData {},
            args,
        }
    }
}

impl<'a> AbstractCommandInterface for RunCommand<'a> {
    fn parse_args(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn execute(&self) -> Result<(), io::Error> {
        Ok(())
    }
}
