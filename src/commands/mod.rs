use std::io;

pub mod configure;
pub mod run;

pub trait AbstractCommandInterface {
    fn parse_args(&mut self) -> Result<(), io::Error>;
    async fn execute(&self) -> Result<(), io::Error>;
}
