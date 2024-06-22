use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use log::warn;
use serde_json::from_slice;

use crate::report::Finding;

pub fn is_new(finding: &Finding, baseline: &HashSet) -> bool {
    !baseline.contains(finding)
}

pub fn load_baseline(baseline_path: &Path) -> Result, HashSet, serde_json::Error> {
    let bytes = fs::read(baseline_path)?;
    let findings: Vec = from_slice(&bytes)?;
    Ok(findings.into_iter().collect())
}

pub fn add_baseline(detector: &mut Detector, baseline_path: &str, source: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !baseline_path.is_empty() {
        let absolute_source = PathBuf::from(source).canonicalize()?;
        let absolute_baseline = PathBuf::from(baseline_path).canonicalize()?;

        let relative_baseline = match absolute_baseline.strip_prefix(&absolute_source) {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => {
                warn!("Baseline path is not within the source directory. Ignoring baseline.");
                return Ok(());
            }
        };

        let baseline = load_baseline(&absolute_baseline)?;
        detector.baseline = Some(baseline);
        detector.baseline_path = Some(relative_baseline);
    }

    Ok(())
}