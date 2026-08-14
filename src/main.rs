use std::process::ExitCode;

use clap::Parser;

use logwatch::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match logwatch::cli::run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("logwatch: {error}");
            ExitCode::from(1)
        }
    }
}
