# cli

- `Carfo.toml` at root directory will be used to define the project member directory as `crates/..` in `member` field. eg. `member = ["crates/ks", "crates/ks-cli"]`
- `exclude` field in `Carfo.toml` can be used to exclude some directories from being included in the project. eg. `exclude = ["assets", "resources"]`