use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::io;
use std::io::Read;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{handshake::client::Request, Message},
};

use crate::{
    file_exists, get_os_specific_user_root_config_path,
    models::toml_model::{ProjectRootConfig, UserRootConfig},
    read_file,
};

use super::AbstractCommandInterface;

pub struct RunCommand {
    workspace: String,
    project: String,
    environment: String,
    api_key: String,
    private_key: String,
}

impl RunCommand {
    pub fn new() -> RunCommand {
        RunCommand {
            workspace: String::new(),
            project: String::new(),
            environment: String::new(),
            api_key: String::new(),
            private_key: String::new(),
        }
    }

    fn read_keyshade_toml(&self) -> Result<ProjectRootConfig, io::Error> {
        // Check if the keyshade.toml exists
        if !file_exists!("keyshade.toml") {
            panic!("keyshade.toml not found. Please run `keyshade configure` first.");
        }

        // Read the keyshade.toml
        let keyshade_toml_content = read_file!("keyshade.toml");

        // Parse the keyshade.toml
        let keyshade_toml: ProjectRootConfig = toml::from_str(&keyshade_toml_content).unwrap();

        Ok(keyshade_toml)
    }

    fn read_user_root_toml(&self, project: &String) -> Result<UserRootConfig, io::Error> {
        // Check if the user root toml exists
        let user_root_toml_path = get_os_specific_user_root_config_path!(project);
        if !file_exists!(&user_root_toml_path) {
            panic!("User root toml not found. Please run `keyshade configure` first.");
        }

        // Read the user root toml
        let user_root_toml_content = read_file!(&user_root_toml_path);

        // Parse the user root toml
        let user_root_toml: UserRootConfig = toml::from_str(&user_root_toml_content).unwrap();

        Ok(user_root_toml)
    }
}

impl AbstractCommandInterface for RunCommand {
    fn parse_args(&mut self) -> Result<(), io::Error> {
        let keyshade_toml = self.read_keyshade_toml().unwrap();
        let user_root_toml = self.read_user_root_toml(&keyshade_toml.project).unwrap();

        self.workspace = keyshade_toml.workspace;
        self.project = keyshade_toml.project;
        self.environment = keyshade_toml.environment;
        self.api_key = user_root_toml.api_key;
        self.private_key = user_root_toml.private_key;

        Ok(())
    }

    async fn execute(&self) -> Result<(), io::Error> {
        print!("Running the project: ");
        println!(
            "{} {} {} {}",
            self.workspace, self.project, self.environment, self.api_key
        );

        // Create a request with the URL and headers
        let request = Request::builder()
            .uri("ws://localhost:4200/change-notifier")
            .header("x-keyshade-token", &self.api_key)
            .header("sec-websocket-key", &self.private_key)
            .header("host", "localhost:4200")
            .body(())
            .expect("Failed to build request");

        // Connect to the WebSocket server with the custom headers
        let (ws_stream, _) = connect_async(request)
            .await
            .expect("Failed to connect to WebSocket server");

        println!("Connected");

        let (mut write, mut read) = ws_stream.split();

        // Register client app
        let register_message = json!({
            "workspaceName": self.workspace,
            "projectName": self.project,
            "environmentName": self.environment
        });

        write
            .send(Message::Text(register_message.to_string()))
            .await
            .expect("Failed to send register message");

        // Listen for configuration-updated messages
        while let Some(message) = read.next().await {
            match message {
                Ok(msg) => match msg {
                    Message::Text(text) => println!("Change received: {}", text),
                    _ => (),
                },
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
