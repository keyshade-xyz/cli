#[macro_export]
/// Reads a line of input from the terminal.
///
/// # Arguments
///
/// * `$prompt` - The prompt to display to the user.
///
/// # Returns
///
/// A string representation of the user input.
///
/// # Example
///
/// ```rust
/// let input: String = read_from_terminal!("Enter your name:").unwrap();
/// println!("{}", input);
/// ```
macro_rules! read_from_terminal {
    ($prompt:expr) => {{
        let mut input = String::new();
        print!("{}", $prompt);
        ::std::io::stdout().flush().unwrap();
        ::std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }};
}

#[macro_export]
/// Reads a line of input securely from the terminal.
///
/// # Arguments
///
/// * `$prompt` - The prompt to display to the user.
///
/// # Returns
///
/// A string representation of the user input.
///
/// # Example
///
/// ```rust
/// let input: String = read_securely_from_terminal!("Enter your password:").unwrap();
/// println!("{}", input);
/// ```
macro_rules! read_securely_from_terminal {
    ($prompt:expr) => {{
        let input = ::inquire::Password::new($prompt)
            .without_confirmation()
            .prompt()
            .unwrap();
        input.trim().to_string()
    }};
}
