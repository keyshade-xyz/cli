mod commands;
mod constants;
mod macros;
mod models;
fn main() {
    commands::main();
    // let workspace_str =
    //     generate_workspace_toml!("my_workspace", None, "", "");
    // println!("{}", workspace_str);

    // let project_str = generate_project_toml!("my_project", "api_key", "private_key");
    // println!("{}", project_str);

    // let config_str: String = generate_config_toml!("my_workspace", None, "", "");
    // println!("{}", config_str);
}
