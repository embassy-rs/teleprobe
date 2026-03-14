pub mod api;
pub mod auth;
pub mod client;
pub mod config;
pub mod logutil;
pub mod probe;
pub mod run;
pub mod server;
pub mod util;

include!(concat!(env!("OUT_DIR"), "/meta.rs"));

use std::time::{Duration, Instant};

use clap::Parser;

use crate::run::Options;

#[derive(clap::Parser)]
#[clap(version = "1.0", author = "Dario Nieuwenhuis <dirbaio@dirbaio.net>")]
enum Cli {
    Local {
        #[clap(subcommand)]
        command: LocalCommand,
    },
    Server {
        #[clap(long, default_value_t = 8080)]
        port: u16,
    },
    Client(client::Command),
}

#[derive(clap::Subcommand)]
enum LocalCommand {
    ListProbes,
    Run {
        /// ELF file to flash+run
        file: String,

        /// Set job timeout
        #[clap(short)]
        timeout: Option<u64>,

        #[clap(flatten)]
        probe: crate::probe::Opts,
    },
}

fn main() -> anyhow::Result<()> {
    logutil::init();

    // force capture backtraces
    //std::env::set_var("RUST_BACKTRACE", "1");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Local { command } => match command {
            LocalCommand::ListProbes => crate::probe::list(),
            LocalCommand::Run { file, timeout, probe } => {
                let elf = std::fs::read(file)?;
                let mut sess = crate::probe::connect(&probe)?;

                let opts = Options {
                    deadline: timeout.map(|t| Instant::now() + Duration::from_secs(t)),
                    ..Default::default()
                };
                crate::run::run(&mut sess, &elf, opts)
            }
        },
        Cli::Server { port } => crate::server::serve(port).await,
        Cli::Client(cmd) => client::main(cmd).await,
    }
}
