use lazy_static::lazy_static;
use rand::prelude::*;
use regex::Regex;
use reggen::Generator;
use std::sync::Mutex;

lazy_static! {
    static ref RNG: Mutex<ThreadRng> = Mutex::new(rand::thread_rng());
}

/// Generates a secret string based on the provided regular expression.
///
/// # Arguments
///
/// * `regex` - A string slice containing the regular expression.
///
/// # Returns
///
/// A string containing the generated secret.
///
/// # Panics
///
/// Panics if the regular expression is invalid or if secret generation fails.
pub fn new_secret(regex: &str) -> String {
    let mut rng = RNG.lock().unwrap();
    let generator = Generator::new(regex, &mut *rng).unwrap();
    generator.generate()
}