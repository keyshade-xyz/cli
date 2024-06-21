use std::io::{self, Write};

use inquire::Password;

pub fn read_from_terminal(prompt: &str) -> Result<String, io::Error> {
    let mut input = String::new();
    print!("{}", prompt);
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn read_securely_from_terminal(prompt: &str) -> Result<String, io::Error> {
    let input = Password::new("Enter your API Key:")
        .without_confirmation()
        .prompt()
        .unwrap();
    Ok(input.trim().to_string())
}
