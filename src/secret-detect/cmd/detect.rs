use std::time::Instant;
use std::process::exit;

use clap::{arg, ArgMatches, Command};
use log::{error, info, LevelFilter};
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
use std::io::{self, Read};

use crate::config::Config;
use crate::detect::Detector;
use crate::report::{Finding, FindingSummary};
use crate::sources::{DirectoryTargets, GitLogCmd, PipeReader};

// Function to initialize logging based on verbosity level
fn init_logging(verbose: u64) {
    let log_level = match verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let config = ConfigBuilder::new()
        .set_target_level(log_level)
        .set_thread_level(LevelFilter::Off)
        .build();

    TermLogger::init(
        log_level,
        config,
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();
}

// Function to run the detect command
pub fn run_detect(matches: &ArgMatches) {
    let start_time = Instant::now();

    // Initialize logging
    init_logging(matches.get_count("verbose") as u64);

    // Load the configuration
    let config = match Config::load_from_file(matches.get_one::<String>("config").unwrap()) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            exit(1);
        }
    };

    // Get source path
    let source_path = matches.get_one::<String>("source").unwrap();

    // Create the detector
    let mut detector = Detector::new(&config, source_path);

    // Determine the scan type
    let no_git = matches.get_flag("no-git");
    let from_pipe = matches.get_flag("pipe");

    // Perform the scan
    let findings: Vec<Finding> = if no_git {
        // Scan directory
        match DirectoryTargets::new(source_path, detector.sema.clone(), detector.follow_symlinks) {
            Ok(paths) => match detector.detect_files(&paths) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to scan directory: {}", e);
                    vec![] // Return an empty vector on error
                }
            },
            Err(e) => {
                error!("Failed to get directory targets: {}", e);
                exit(1);
            }
        }
    } else if from_pipe {
        // Scan from pipe
        let mut buffer = String::new();
        match io::stdin().read_to_string(&mut buffer) {
            Ok(_) => match detector.detect_reader(&buffer) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to scan from pipe: {}", e);
                    exit(1);
                }
            },
            Err(e) => {
                error!("Failed to read from pipe: {}", e);
                exit(1);
            }
        }
    } else {
        // Scan git history
        let log_opts = matches.get_one::<String>("log-opts").unwrap();
        match GitLogCmd::new(source_path, log_opts) {
            Ok(git_cmd) => match detector.detect_git(&git_cmd) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to scan git history: {}", e);
                    vec![] // Return an empty vector on error
                }
            },
            Err(e) => {
                error!("Failed to create git log command: {}", e);
                exit(1);
            }
        }
    };

    // Create the finding summary
    let finding_summary = FindingSummary::new(&findings, start_time.elapsed(), config);

    // Handle the findings and exit
    finding_summary.handle_findings(&matches);
}

// Function to write the configuration to a file
fn write_config_to_file(config: &Config, output_path: &str) -> Result<(), std::io::Error> {
    let mut file = File::create(output_path)?;
    // Template file or logic to generate the TOML content
    let toml_content = config.generate_toml(); 
    file.write_all(toml_content.as_bytes())?;
    Ok(())
}

// CLI definition using clap
pub fn cli() -> Command {
    Command::new("gitleaks")
        .about("Detect secrets in code")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("detect")
                .about("Detect secrets")
                .arg(arg!(-c --config <CONFIG> "Path to gitleaks.toml config file").required(true))
                .arg(arg!(-s --source <SOURCE> "Source to scan (file, directory, or git repository URL)").required(true))
                .arg(arg!(--no-git "Treat git repo as a regular directory"))
                .arg(arg!(--pipe "Scan input from stdin"))
                .arg(arg!(-l --log-opts <LOG_OPTS> "Git log options (only applicable for git scans)"))
                .arg(arg!(-e --exit-code <EXIT_CODE> "Exit code to use if secrets are found (default: 1)").default_value("1"))
                .arg(arg!(-v ... "Increase verbosity level"))
        )
}