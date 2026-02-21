mod cli;
mod commands;
mod mft;
mod models;
mod output;
mod rules;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Extract { image, out } => {
            commands::extract::run(image, out);
        }
        Commands::Parse { path, out_json, data } => {
            commands::parse::run(path, out_json, *data);
        }
        Commands::Play { image, out, data } => {
            commands::play::run(image, out, *data);
        }
    }
}