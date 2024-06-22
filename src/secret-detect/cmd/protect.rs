use std::time::Instant;
use std::process::exit;

use clap::{arg, ArgMatches, Command};
use log::{error, info, LevelFilter};
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};

use crate::config::Config;
use crate::detect::Detector;
use crate::report::{Finding, FindingSummary};
use crate::sources::GitDiffCmd;

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


// Function to run the protect command
pub fn run_protect(matches: &ArgMatches) {
    let start_time = Instant::now();

    // Initialize logging
    init_logging(matches.get_count("verbose") as u64);

    // Load the configuration
    let config = match Config::load_from_file(matches.get_one::<String>("config").unwrap()) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Error loading config: {}", e);
            exit(1);
        }
    };

    let source = matches.get_one::<String>("source").unwrap();
    let staged = matches.get_flag("staged");
    let exit_code = matches.get_one::<i32>("exit-code").unwrap_or(&0);

    let detector = Detector::new(&config, source.clone());
    let git_cmd = match GitDiffCmd::new(source, staged) {
        Ok(cmd) => cmd,
        Err(e) => {
            error!("Error creating GitDiffCmd: {}", e);
            exit(1);
        }
    };

    let findings = match detector.detect_git(&git_cmd) {
        Ok(f) => f,
        Err(e) => {
            error!("Error during detection: {}", e);
            Vec::new()
        }
    };

    finding_summary_and_exit(&findings, &config, *exit_code, start_time);
}

// Function to print finding summary and exit with appropriate code
fn finding_summary_and_exit(findings: &[Finding], config: &Config, exit_code: i32, start_time: Instant) {
    let summary = FindingSummary::new(findings, config, start_time.elapsed());

    if !findings.is_empty() {
        summary.print();
    }

    if summary.has_secrets() {
        info!(
            "{} secrets detected in {}.",
            summary.total_findings, summary.duration
        );
        exit(exit_code);
    }

    info!("No secrets detected in {}.", summary.duration);
}