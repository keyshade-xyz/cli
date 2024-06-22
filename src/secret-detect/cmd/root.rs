use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::process::exit;

use clap::{arg, ArgMatches, Command};
use log::{error, info, warn, LevelFilter};
use simplelog::{ColorChoice, CombinedLogger, ConfigBuilder, TermLogger, TerminalMode, WriteLogger};

use crate::config::{Config, Rule};
use crate::detect::Detector;
use crate::report::{Finding, FindingSummary, write_report};
use crate::sources::{
    DirectoryTargets, GitDiffCmd, GitLogCmd, PipeReader, 
};

const BANNER: &str = r#"

................................................................................
................................................................................
................................................................................
............................,,,,,,,,,,,,,,,,,,,.................................
.........................,*#&@@@@@@@@@@@@@@@@@&#/,..............................
.........................*#%@@&&&&&&&&&&&&&&&&&&#*..............................
.........................*#%@@&&&&&&&&&&&&&&&&&&#*..............................
.........................*#%@&&&&&&&&&&&&&&&&&&&#*..............................
.........................*#%@&&&&&&&&&&&&&&&&&&&#*..............................
.........,(#%##(/*,......*#%&&&&&&&&&&&&&&&&&&&&#*......,*/(##%#(,..............
.......,*(&@&&&&&&&%%(/*,*#%&&&&&&&&&&&&&&&&&&&&#*,*/(#%&&&&&&&@&#/,............
.......*%&&&&&&&&&&&&@@@@@@@&&&&&&&&&&&&&&&&&&&&&&&@@@&&&&&&&&&&&&%*............
.....,*(&@&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@&#/,..........
.....*%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%*..........
...,*(&@&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&@&#/,........
...*#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#*........
...*%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%*........
. ..,/#%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%#/,..  .....
      ...,*(#%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%(*,...      .....
             ..,/(#%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%#(/*..                  
                 .*(&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(*.                      
               .,/%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%(,.                    
             .,/%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%/,.                  
           .,/%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%/,.                
         .,/%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%/*.              
        .*(%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%(,              
         ,*(%&&&&&&&&&&&&&&&&&&&&&%(*,,(%&&&&&&&&&&&&&&&&&&&&&%(/.              
           .*/#%&&&&&&&&&&&&&&&&%(*.   .*(%&&&&&&&&&&&&&&&&%#(*..               
             ..,/(%&&&&&&&&&&&&(*.      ..*(%&&&&&&&&&&&%(/,..                  
                 .,*(%&&&&&&&(*..          .,(%&&&&&&%(*,.                      
                     .*(#%%(*.               .,(%%%(*.                          
                                                                                
                                                                                

/$$                                     /$$                       /$$          
| $$                                    | $$                      | $$          
| $$   /$$  /$$$$$$  /$$   /$$  /$$$$$$$| $$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$ 
| $$  /$$/ /$$__  $$| $$  | $$ /$$_____/| $$__  $$ |____  $$ /$$__  $$ /$$__  $$
| $$$$$$/ | $$$$$$$$| $$  | $$|  $$$$$$ | $$  \ $$  /$$$$$$$| $$  | $$| $$$$$$$$
| $$_  $$ | $$_____/| $$  | $$ \____  $$| $$  | $$ /$$__  $$| $$  | $$| $$_____/
| $$ \  $$|  $$$$$$$|  $$$$$$$ /$$$$$$$/| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$
|__/  \__/ \_______/ \____  $$|_______/ |__/  |__/ \_______/ \_______/ \_______/
                     /$$  | $$                                                  
                    |  $$$$$$/                                                    keyshade secret scanner
                     \______/                                                   

"#;

// Function to initialize logging based on verbosity level and color choice
fn init_logging(verbose: u64, no_color: bool) {
    let log_level = match verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let config = ConfigBuilder::new()
        .set_target_level(log_level)
        .set_thread_level(LevelFilter::Off)
        .build();

    let term_logger = TermLogger::new(
        log_level,
        config.clone(),
        TerminalMode::Mixed,
        if no_color { ColorChoice::Never } else { ColorChoice::Auto },
    );

    // Combine the terminal logger with a file logger if the environment variable is set
    if let Ok(log_file) = std::env::var("GITLEAKS_LOG_FILE") {
        let file = File::create(log_file).expect("Failed to create log file");
        let file_logger = WriteLogger::new(log_level, config, file);
        CombinedLogger::init(vec![term_logger.unwrap(), file_logger]).unwrap();
    } else {
        TermLogger::init(
            log_level,
            config,
            TerminalMode::Mixed,
            if no_color { ColorChoice::Never } else { ColorChoice::Auto },
        )
        .unwrap();
    }
}

// Function to run the detect command
pub fn run_detect(matches: &ArgMatches) {
    let start_time = Instant::now();

    // Initialize logging
    let no_color = matches.get_flag("no-color");
    init_logging(matches.get_count("verbose") as u64, no_color);

    // Load the configuration
    let config = match Config::load_from_file_or_default(matches.get_one::<String>("config")) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config: {}", e);
            exit(1);
        }
    };

    let source = matches.get_one::<String>("source").unwrap_or(".");
    let mut detector = Detector::new(config);

    // Override enabled rules if specified
    if let Some(rule_ids) = matches.get_many::<String>("enable-rule") {
        detector.config.rules = override_enabled_rules(detector.config.rules.clone(), rule_ids);
    }

    // Add baseline if specified
    if let Some(baseline_path) = matches.get_one::<String>("baseline-path") {
        if let Err(e) = detector.add_baseline(baseline_path, source) {
            error!("Failed to load baseline: {}", e);
        }
    }

    // Add .gitleaksignore if specified or found in default locations
    let gitleaks_ignore_path = matches.get_one::<String>("keyshade-ignore-path").unwrap_or(".");
    add_gitleaks_ignore(&mut detector, gitleaks_ignore_path, source);

    detector.verbose = matches.get_flag("verbose");
    detector.redact = matches.get_one::<u8>("redact").cloned().unwrap_or(100);
    detector.max_target_megabytes = matches.get_one::<usize>("max-target-megabytes").cloned().unwrap_or(0);
    detector.ignore_gitleaks_allow = matches.get_flag("ignore-keyshade-allow");
    detector.follow_symlinks = matches.get_flag("follow-symlinks");

    // Determine the scan type and execute
    let no_git = matches.get_flag("no-git");
    let from_pipe = matches.get_flag("pipe");

    let findings = if no_git {
        match DirectoryTargets::new(source, detector.sema.clone(), detector.follow_symlinks) {
            Ok(paths) => match detector.detect_files(paths) {
                Ok(findings) => findings,
                Err(e) => {
                    error!("Error during file scan: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                error!("Failed to get directory targets: {}", e);
                exit(1);
            }
        }
    } else if from_pipe {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).unwrap();
        match PipeReader::new(buffer.as_str()) {
            Ok(reader) => match detector.detect_reader(reader, 10) {
                Ok(findings) => findings,
                Err(e) => {
                    error!("Error during pipe scan: {}", e);
                    exit(1);
                }
            },
            Err(e) => {
                error!("Error creating pipe reader: {}", e);
                exit(1);
            }
        }
    } else {
        let log_opts = matches.get_one::<String>("log-opts").cloned().unwrap_or_default();
        match GitLogCmd::new(source, log_opts) {
            Ok(git_cmd) => match detector.detect_git(git_cmd) {
                Ok(findings) => findings,
                Err(e) => {
                    error!("Error during git scan: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                error!("Failed to get git log command: {}", e);
                exit(1);
            }
        }
    };

    finding_summary_and_exit(
        findings,
        matches,
        detector.config,
        start_time,
    );
}

// Function to run the protect command
pub fn run_protect(matches: &ArgMatches) {
    let start_time = Instant::now();

    // Initialize logging
    let no_color = matches.get_flag("no-color");
    init_logging(matches.get_count("verbose") as u64, no_color);

    // Load the configuration
    let config = match Config::load_from_file_or_default(matches.get_one::<String>("config")) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config: {}", e);
            exit(1);
        }
    };

    let source = matches.get_one::<String>("source").unwrap_or(".");
    let detector = Detector::new(config);
    let staged = matches.get_flag("staged");

    let git_cmd = match GitDiffCmd::new(source, staged) {
        Ok(cmd) => cmd,
        Err(e) => {
            error!("Failed to create git diff command: {}", e);
            exit(1);
        }
    };

    let findings = match detector.detect_git(git_cmd) {
        Ok(findings) => findings,
        Err(e) => {
            error!("Error during git diff scan: {}", e);
            Vec::new()
        }
    };

    finding_summary_and_exit(
        findings,
        matches,
        detector.config,
        start_time,
    );
}

// Function to handle finding summary and exit code
fn finding_summary_and_exit(
    findings: Vec<Finding>, 
    matches: &ArgMatches, 
    config: Config, 
    start_time: Instant,
) {
    let elapsed = start_time.elapsed();
    let summary = FindingSummary::from_findings(&findings);
    
    if summary.leaks > 0 {
        warn!(
            "{} leak{} detected in {}. {}",
            summary.leaks,
            if summary.leaks == 1 { "" } else { "s" },
            format_duration(elapsed),
            if summary.errors > 0 {
                format!("({} error{} occurred during the scan)", summary.errors, if summary.errors == 1 { "" } else { "s" })
            } else {
                "".to_string()
            }
        );
    } else {
        info!(
            "No leaks detected in {}. {}",
            format_duration(elapsed),
            if summary.errors > 0 {
                format!("({} error{} occurred during the scan)", summary.errors, if summary.errors == 1 { "" } else { "s" })
            } else {
                "".to_string()
            }
        );
    }

    // Write report if a path is specified
    if let Some(report_path) = matches.get_one::<String>("report-path") {
        let report_format = matches.get_one::<String>("report-format").unwrap_or("json");
        if let Err(e) = write_report(&findings, &config, report_format, report_path) {
            error!("Failed to write report: {}", e);
        }
    }

    // Exit with appropriate code
    let exit_code = matches.get_one::<i32>("exit-code").cloned().unwrap_or(1);
    if summary.leaks > 0 {
        exit(exit_code as i32);
    }
}

// Function to format duration into a human-readable string
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        return format!("{} seconds", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{} minutes {} seconds", mins, secs % 60);
    }
    let hours = mins / 60;
    return format!("{} hours {} minutes {} seconds", hours, mins % 60, secs % 60);
}

// Helper function to check if a file exists
fn file_exists(file_path: &str) -> bool {
    fs::metadata(file_path).is_ok()
}

// Function to add .gitleaksignore files to the detector
fn add_gitleaks_ignore(detector: &mut Detector, gitleaks_ignore_path: &str, source: &str) {
    if file_exists(gitleaks_ignore_path) {
        if let Err(e) = detector.add_gitleaks_ignore(gitleaks_ignore_path) {
            error!("Failed to add .gitleaksignore: {}", e);
        }
    }

    let default_paths = [
        filepath::join(gitleaks_ignore_path, ".gitleaksignore"),
        filepath::join(source, ".gitleaksignore"),
    ];

    for path in default_paths {
        if file_exists(&path) {
            if let Err(e) = detector.add_gitleaks_ignore(&path) {
                error!("Failed to add .gitleaksignore: {}", e);
            }
        }
    }
}

// Function to override enabled rules based on user input
fn override_enabled_rules(
    mut rules: HashMap<String, Rule>,
    rule_ids: impl Iterator<Item = String>,
) -> HashMap<String, Rule> {
    let mut enabled_rules = HashMap::new();
    for rule_id in rule_ids {
        if let Some(rule) = rules.remove(&rule_id) {
            enabled_rules.insert(rule_id, rule);
        } else {
            error!("Requested rule {} not found in rules", rule_id);
        }
    }
    enabled_rules
}

// Main function to execute the CLI application
pub fn execute() {
    let matches = Command::new("keyshade")
        .version(clap::crate_version!())
        .about("keyshade scans code, past or present, for secrets")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("detect")
                .about("Detect secrets in code")
                .arg(arg!(<SOURCE> "Path to source").default_value("."))
                .arg(
                    arg!(-c --config <CONFIG> "Config file path")
                        .required(false)
                )
                .arg(
                    arg!(-e --("exit-code") <EXIT_CODE> "Exit code when leaks have been encountered")
                        .default_value("1")
                        .validator(|s| s.parse::<i32>())
                )
                .arg(arg!(-r --("report-path") <REPORT_PATH> "Report file").required(false))
                .arg(
                    arg!(-f --("report-format") <REPORT_FORMAT> "Output format (json, csv, junit, sarif)")
                        .default_value("json")
                        .required(false)
                )
                .arg(arg!(-b --("baseline-path") <BASELINE_PATH> "Path to baseline with issues that can be ignored").required(false))
                .arg(
                    arg!(-l --("log-level") <LOG_LEVEL> "Log level (trace, debug, info, warn, error, fatal)")
                        .default_value("info")
                        .required(false)
                )
                .arg(arg!(-v --verbose "Show verbose output from scan").required(false))
                .arg(arg!(--"no-color" "Turn off color for verbose output").required(false))
                .arg(
                    arg!(--"max-target-megabytes" <MAX_TARGET_MEGABYTES> "Files larger than this will be skipped")
                        .default_value("0")
                        .validator(|s| s.parse::<usize>())
                        .required(false)
                )
                .arg(arg!(--"ignore-keyshade-allow" "Ignore keyshade:allow comments").required(false))
                .arg(
                    arg!(-u --redact <REDACT> "Redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
                        .default_value("100")
                        .validator(|s| s.parse::<u8>())
                        .required(false)
                )
                .arg(arg!(--"no-git" "Treat git repo as a regular directory and scan those files").required(false))
                .arg(arg!(--pipe "Scan input from stdin").required(false))
                .arg(arg!(--"log-opts" <LOG_OPTS> "Git log options").required(false))
                .arg(
                    arg!(-R --("enable-rule") <ENABLE_RULE> ... "Only enable specific rules by id")
                        .required(false)
                )
                .arg(
                    arg!(-i --("keyshade-ignore-path") <GITLEAKS_IGNORE_PATH> "Path to .gitleaksignore file or folder containing one")
                        .default_value(".")
                        .required(false)
                )
                .arg(arg!(--"follow-symlinks" "Scan files that are symlinks to other files").required(false)),
        )
        .subcommand(
            Command::new("protect")
                .about("Protect secrets in code")
                .arg(arg!(<SOURCE> "Path to source").default_value("."))
                .arg(
                    arg!(-c --config <CONFIG> "Config file path")
                        .required(false)
                )
                .arg(
                    arg!(-e --("exit-code") <EXIT_CODE> "Exit code when leaks have been encountered")
                        .default_value("1")
                        .validator(|s| s.parse::<i32>())
                )
                .arg(arg!(-r --("report-path") <REPORT_PATH> "Report file").required(false))
                .arg(
                    arg!(-f --("report-format") <REPORT_FORMAT> "Output format (json, csv, junit, sarif)")
                        .default_value("json")
                        .required(false)
                )
                .arg(arg!(-b --("baseline-path") <BASELINE_PATH> "Path to baseline with issues that can be ignored").required(false))
                .arg(
                    arg!(-l --("log-level") <LOG_LEVEL> "Log level (trace, debug, info, warn, error, fatal)")
                        .default_value("info")
                        .required(false)
                )
                .arg(arg!(-v --verbose "Show verbose output from scan").required(false))
                .arg(arg!(--"no-color" "Turn off color for verbose output").required(false))
                .arg(
                    arg!(--"max-target-megabytes" <MAX_TARGET_MEGABYTES> "Files larger than this will be skipped")
                        .default_value("0")
                        .validator(|s| s.parse::<usize>())
                        .required(false)
                )
                .arg(arg!(--"ignore-keyshade-allow" "Ignore keyshade:allow comments").required(false))
                .arg(
                    arg!(-u --redact <REDACT> "Redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
                        .default_value("100")
                        .validator(|s| s.parse::<u8>())
                        .required(false)
                )
                .arg(arg!(--staged "Detect secrets in a staged state").required(false))
                .arg(
                    arg!(-i --("keyshade-ignore-path") <GITLEAKS_IGNORE_PATH> "Path to .gitleaksignore file or folder containing one")
                        .default_value(".")
                        .required(false)
                )
                .arg(arg!(--"follow-symlinks" "Scan files that are symlinks to other files").required(false)),
        )
        .get_matches();

    if let Some(banner) = std::env::var("GITLEAKS_BANNER").ok() {
        if banner != "false" {
            println!("{}", BANNER);
        }
    } else {
        println!("{}", BANNER);
    }

    match matches.subcommand() {
        Some(("detect", matches)) => {
            run_detect(matches);
        }
        Some(("protect", matches)) => {
            run_protect(matches);
        }
        _ => unreachable!(),
    }
}