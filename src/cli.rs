use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ja4finger", version, about = "JA4 fingerprinting CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Capture live traffic from a Linux interface using YAML config
    Daemon {
        /// Path to daemon YAML config file
        #[arg(long)]
        config: String,
    },
    /// Analyze packets from a pcap file
    Pcap {
        /// Path to a pcap file
        #[arg(long)]
        file: String,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}
