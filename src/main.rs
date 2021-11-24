mod config;
mod log_capture;
mod logger;
mod oidc;
mod probe;
mod run;
mod server;

use clap::Parser;
use std::fs;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Parser)]
#[clap(version = "1.0", author = "Dario Nieuwenhuis <dirbaio@dirbaio.net>")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    Run(RunCmd),
    Server(ServerCmd),
}

#[derive(Parser)]
pub struct RunCmd {
    /// ELF file to flash+run
    #[clap(long)]
    pub elf: String,

    #[clap(flatten)]
    probe: probe::Opts,
}

#[derive(Parser)]
pub struct ServerCmd {}

fn main() -> anyhow::Result<()> {
    let mut builder = env_logger::Builder::new();
    if let Ok(s) = ::std::env::var("RUST_LOG") {
        builder.parse_filters(&s);
    } else {
        builder.filter_module("teleprobe", log::LevelFilter::Info);
        builder.filter_module("device", log::LevelFilter::Trace);
    }
    logger::init(Box::new(builder.build()));

    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Run(cmd) => run(cmd),
        SubCommand::Server(cmd) => server(cmd),
    }
}

fn run(cmd: RunCmd) -> anyhow::Result<()> {
    let elf = fs::read(cmd.elf)?;
    let mut sess = probe::connect(cmd.probe)?;

    let mut opts = run::Options::default();
    run::run(&mut sess, &elf, opts)
}

fn server(cmd: ServerCmd) -> anyhow::Result<()> {
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(server::serve())
}
