#[macro_export]
macro_rules! get_os_specific_user_root_config_path {
    ($project: expr) => {{
        if cfg!(windows) {
            format!(
                "C:\\Users\\{}\\.keyshade\\{}.toml",
                ::whoami::username(),
                $project
            )
        } else {
            format!("/home/{}/.keyshade/{}.toml", ::whoami::username(), $project)
        }
    }};
}

#[macro_export]
macro_rules! generate_user_root_toml {
    ($api_key: expr, $private_key: expr, $project: expr) => {{
        let mut user_root_map = ::std::collections::HashMap::new();
        user_root_map.insert("api_key".to_string(), $api_key);
        user_root_map.insert("private_key".to_string(), $private_key);
        ::toml::to_string_pretty(&user_root_map).unwrap()
    }};
}

#[macro_export]
macro_rules! generate_project_toml {
    ($workspace: expr, $project: expr, $environment: expr) => {{
        let mut project_map = ::std::collections::HashMap::new();
        project_map.insert("workspace".to_string(), $workspace);
        project_map.insert("project".to_string(), $project);
        project_map.insert("environment".to_string(), $environment);
        ::toml::to_string_pretty(&project_map).unwrap()
    }};
}
