#[macro_export]
macro_rules! file_exists {
    ($file_name:expr) => {{
        ::std::fs::metadata($file_name).is_ok()
    }};
}

#[macro_export]
macro_rules! read_file {
    ($file_name:expr) => {{
        let mut file = ::std::fs::File::open($file_name).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents
    }};
}

#[macro_export]
macro_rules! write_file {
    ($file_name:expr, $contents:expr) => {{
        let path = ::std::path::Path::new($file_name);

        // Create the parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            ::std::fs::create_dir_all(parent).unwrap();
        }

        // Write the contents to the file
        let mut file = ::std::fs::File::create(&path).unwrap();
        file.write_all($contents.as_bytes()).unwrap();
    }};
}
