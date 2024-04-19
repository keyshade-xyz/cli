use std::{collections::HashMap, process::Command};

use clap::ArgMatches;

pub fn run(sub_m: &ArgMatches) {
    let mut env_vars: HashMap<String, String> = HashMap::new();
    env_vars.insert("NAME".to_string(), "Sawan".to_string());
    env_vars.insert("AGE".to_string(), "21".to_string());
    env_vars.insert("COUNTRY".to_string(), "India".to_string());

    let command: Vec<&str> = sub_m
        .get_many::<String>("COMMAND")
        .unwrap_or_default()
        .map(|v| v.as_str())
        .collect::<Vec<_>>();
    if let Some((program, args)) = command.split_first() {
        let output = Command::new(program).args(args).envs(env_vars).output();

        match output {
            Ok(output) => {
                // Print the output
                if !output.stdout.is_empty() {
                    println!("{}", String::from_utf8_lossy(&output.stdout));
                }
                // Print the error
                if !output.stderr.is_empty() {
                    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                eprintln!("Failed to execute command: {}", e);
            }
        }
    } else {
        println!("No command provided");
    }
}
