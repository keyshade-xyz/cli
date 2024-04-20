#[macro_export]
/// Macro to generate a TOML string representation of a project.
///
/// # Arguments
///
/// * `$project` - The project name.
/// * `$api_key` - The API key for the project.
/// * `$private_key` - The private key for the project.
///
/// # Returns
///
/// A string representation of the project in TOML format.
///
/// # Example
///
/// ```rust
/// let project_toml: String = generate_project_toml!("MyProject", "api_key", "private_key");
/// println!("{}", project_toml);
/// ```
macro_rules! generate_project_toml {
    ($project:expr, $api_key:expr, $private_key:expr) => {{
        let mut project_map = ::std::collections::HashMap::new();
        project_map.insert(
            $project.to_string(),
            $crate::models::toml_model::Project {
                api_key: $api_key.to_string(),
                private_key: $private_key.to_string(),
            },
        );
        ::toml::to_string_pretty(&project_map).unwrap()
    }};
}

#[macro_export]
/// Generates a TOML string representation of a workspace with the given parameters.
///
/// # Arguments
///
/// * `$wrkspc` - The workspace name.
/// * `$prjct` - An optional project name.
/// * `$api_key_input` - The API key input.
/// * `$private_key_input` - The private key input.
///
/// # Returns
///
/// A TOML string representation of the workspace.
///
/// # Example
///
/// ## Workspace with a project
///
/// ```rust
/// let workspace_toml: String = generate_workspace_toml!("MyWorkspace", Some("MyProject").to_string(), "api_key", "private_key");
/// println!("{}", workspace_toml);
/// ```
///
/// ## Workspace without a project
///
/// ```rust
/// let workspace_toml: String = generate_workspace_toml!("MyWorkspace", None, "", "");
/// println!("{}", workspace_toml);
/// ```
macro_rules! generate_workspace_toml {
    ($wrkspc:expr, $prjct:expr, $api_key_input:expr, $private_key_input:expr) => {{
        let mut workspace_map = ::std::collections::HashMap::new();
        workspace_map.insert(
            $wrkspc.to_string(),
            $crate::models::toml_model::Workspace {
                projects: match $prjct {
                    Some(prjct) => {
                        let mut project_map = ::std::collections::HashMap::new();
                        project_map.insert(
                            prjct,
                            $crate::models::toml_model::Project {
                                api_key: $api_key_input.to_string(),
                                private_key: $private_key_input.to_string(),
                            },
                        );
                        Some(project_map)
                    }
                    None => None,
                },
            },
        );
        ::toml::to_string_pretty(&workspace_map).unwrap()
    }};
}

#[macro_export]
/// Generates a TOML string representation of a configuration with the given parameters.
///
/// # Arguments
///
/// * `$wrkspc` - The workspace name.
/// * `$prjct` - An optional project name.
/// * `$api_key_input` - The API key input.
/// * `$private_key_input` - The private key input.
///
/// # Returns
///
/// A TOML string representation of the configuration.
///
/// # Example
///
/// ## Configuration with a project
///
/// ```rust
/// let configuration_toml: String = generate_config_toml!("MyWorkspace", Some("MyProject").to_string(), "api_key", "private_key");
/// println!("{}", configuration_toml);
/// ```
///
/// ## Configuration without a project
///
/// ```rust
/// let configuration_toml: String = generate_config_toml!("MyWorkspace", None, "", "");
/// println!("{}", configuration_toml);
/// ```
macro_rules! generate_config_toml {
    ($wrkspc:expr, $prjct:expr, $api_key_input:expr, $private_key_input:expr) => {{
        let mut workspace_map = ::std::collections::HashMap::new();
        workspace_map.insert(
            $wrkspc.to_string(),
            $crate::models::toml_model::Workspace {
                projects: match $prjct {
                    Some(prjct) => {
                        let mut project_map = ::std::collections::HashMap::new();
                        project_map.insert(
                            prjct,
                            $crate::models::toml_model::Project {
                                api_key: $api_key_input.to_string(),
                                private_key: $private_key_input.to_string(),
                            },
                        );
                        Some(project_map)
                    }
                    None => None,
                },
            },
        );

        let config = $crate::models::toml_model::Configure {
            base_url: $crate::constants::BASE_URL.to_string(),
            workspaces: workspace_map,
        };

        ::toml::to_string_pretty(&config).unwrap()
    }};
}
