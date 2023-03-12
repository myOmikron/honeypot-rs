//! # honeypot-rs

#![warn(missing_docs)]

use std::path::Path;
use std::{env, fs};

use clap::Parser;
use log::info;
use pcap::Capture;

use crate::config::Config;

pub mod config;

/// A honeypot written in rust
#[derive(Parser)]
#[clap(version, author = "myOmikron")]
pub struct Cli {
    /// path to retrieve the config file for honeypot-rs from
    #[clap(long)]
    #[clap(default_value_t = String::from("/etc/honeypot-rs/config.toml"))]
    config_path: String,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "debug")
    }

    env_logger::init();

    let cli = Cli::parse();

    let config = get_config(&cli.config_path)?;

    let mut stream = Capture::from_device(config.honeypot.device.as_str())
        .map_err(|err| format!("Could not find device: {err}"))?
        .timeout(100)
        .open()
        .map_err(|e| format!("Could not open dev: {e}"))?;

    stream
        .filter(
            "dst net 127.0.0.0/8 && ! src net 127.0.0.0/8 && (tcp || udp)",
            true,
        )
        .map_err(|err| format!("Could not apply filter: {err}"))?;

    info!("Opened {}", config.honeypot.device);

    while let Ok(packet) = stream.next_packet() {
        println!("{packet:?}");
    }

    Ok(())
}

/// Retrieve the [Config] by a path
///
/// If the file does not exist or could not be parsed, an error is returned
fn get_config(path: &str) -> Result<Config, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("Config file {path} does not exist"));
    }

    if !p.is_file() {
        return Err(format!("Config file {path} is no file"));
    }

    let config_str =
        fs::read_to_string(p).map_err(|e| format!("Error reading from config file: {e}"))?;

    let config =
        toml::from_str(&config_str).map_err(|e| format!("Error parsing config file: {e}"))?;

    Ok(config)
}
