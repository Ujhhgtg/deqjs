use clap::{CommandFactory, Parser};

use crate::cli::{Cli, TopLevel, DecompileCommand, DecompileModeCli, DecompileVersionCli};

mod cli;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(TopLevel::Decompile { command }) => match command {
            DecompileCommand::File {
                path,
                mode,
                version,
                deobfuscate,
                optimize,
            } => {
                let mode = match mode {
                    DecompileModeCli::Pseudo => deqjs_lib::DecompileMode::Pseudo,
                    DecompileModeCli::Disasm => deqjs_lib::DecompileMode::Disasm,
                };
                let version = match version {
                    DecompileVersionCli::Auto => deqjs_lib::DecompileVersion::Auto,
                    DecompileVersionCli::Current => deqjs_lib::DecompileVersion::Current,
                    DecompileVersionCli::Legacy => deqjs_lib::DecompileVersion::Legacy,
                };
                match std::fs::read(&path) {
                    Ok(bytes) => match deqjs_lib::decompile_with_options(
                        &bytes,
                        deqjs_lib::DecompileOptions {
                            mode,
                            version,
                            deobfuscate,
                            optimize,
                        },
                    ) {
                        Ok(out) => {
                            print!("{out}");
                        }
                        Err(e) => {
                            eprintln!("decompile error: {e}");
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("failed to read {path:?}: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Some(TopLevel::Completion { shell }) => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
        }
        None => {
            Cli::command().print_help().unwrap();
        }
    }
}
