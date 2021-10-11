mod config;
mod probe;
mod run;

use clap::{AppSettings, Clap};
use run::Runner;
use std::{fs, sync::atomic::AtomicBool};

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
#[clap(version = "1.0", author = "Dario Nieuwenhuis <dirbaio@dirbaio.net>")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Run(RunCmd),
}

#[derive(Clap)]
pub struct RunCmd {
    /// ELF file to flash+run
    #[clap(long)]
    pub elf: String,

    /// Skip writing the application binary to flash.
    #[clap(long)]
    pub no_flash: bool,

    #[clap(flatten)]
    probe: probe::Opts,
}

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Run(cmd) => run(cmd),
    }
}

fn run(cmd: RunCmd) -> anyhow::Result<()> {
    let elf = fs::read(cmd.elf)?;
    let mut sess = probe::connect(cmd.probe)?;
    let mut runner = Runner::launch(&mut sess, &elf, !cmd.no_flash)?;

    let exit = AtomicBool::new(false);
    runner.run_to_completion(&mut sess, &exit)?;

    Ok(())
}
