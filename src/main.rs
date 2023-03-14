//! # honeypot-rs

#![warn(missing_docs)]

use std::env;
use std::sync::mpsc;

use clap::Parser;
use log::debug;
use nix::unistd::gethostname;

use crate::capture::{start_icmp_capture, start_tcp_capture, start_udp_capture};
use crate::config::get_config;

pub mod capture;
pub mod config;
pub mod packets;

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

    let hostname = gethostname()
        .map_err(|e| format!("Error retrieving hostname: {e}"))?
        .into_string()
        .map_err(|_| "Invalid UTF-8 found in hostname".to_string())?;

    let (tx, rx) = mpsc::channel();

    let _tcp_handle = start_tcp_capture(&hostname, &config.honeypot.device, tx.clone())?;
    let _udp_handle = start_udp_capture(&hostname, &config.honeypot.device, tx.clone())?;
    let _icmp_handle = start_icmp_capture(&hostname, &config.honeypot.device, tx)?;

    while let Ok(packet) = rx.recv() {
        debug!("Received packet: {packet}");
    }

    Ok(())
}
