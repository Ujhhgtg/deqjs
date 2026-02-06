use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum, builder::{Styles, styling::{AnsiColor, Effects}}, crate_description, crate_name, crate_version};
use clap_complete::Shell;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DecompileModeCli {
    Pseudo,
    Disasm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DecompileVersionCli {
    Auto,
    Current,
    Legacy,
}

#[derive(Parser)]
#[command(name = crate_name!(),
    version = crate_version!(),
    about = crate_description!(),
    styles = Styles::styled()
        .header(AnsiColor::BrightGreen.on_default() | Effects::BOLD | Effects::UNDERLINE)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::BrightCyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default()))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<TopLevel>,
}

#[derive(Subcommand)]
pub enum TopLevel {
    /// Decompiles a QuickJS bytecode file
    Decompile {
        #[command(subcommand)]
        command: DecompileCommand,
    },
    /// Generate shell completion
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
pub enum DecompileCommand {
    /// Decompiles a QuickJS bytecode file
    File {
        /// Path to the QuickJS bytecode file
        path: PathBuf,

        /// Output mode
        #[arg(long, value_enum, default_value_t = DecompileModeCli::Pseudo)]
        mode: DecompileModeCli,

        /// Select bytecode version (default: auto-detect)
        #[arg(long, value_enum, default_value_t = DecompileVersionCli::Auto)]
        version: DecompileVersionCli,

        /// Give human readable names to anonymous functions / closures
        #[arg(long, default_value_t = false)]
        deobfuscate: bool,

        /// Apply simple output optimizations to reduce generated pseudo code size
        #[arg(long, default_value_t = false)]
        optimize: bool,
    }
}
