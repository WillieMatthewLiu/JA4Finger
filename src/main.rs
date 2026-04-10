use ja4finger::cli::{self, Command};
use ja4finger::commands::{
    aggregate as aggregate_command, daemon as daemon_command, pcap as pcap_command,
};
use ja4finger::output;
use ja4finger::runtime::RuntimeState;
use std::process::ExitCode;

fn main() -> ExitCode {
    output::init_logging();

    let cli = cli::parse();
    let runtime_state = RuntimeState::default();

    let result = match cli.command {
        Command::Daemon { config } => daemon_command::run(config, &runtime_state),
        Command::Pcap { file } => pcap_command::run(file, &runtime_state),
        Command::Aggregate { file } => aggregate_command::run(file),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
