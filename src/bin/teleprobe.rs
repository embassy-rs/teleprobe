use clap::Parser;
use warp::Future;

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
    Client {
        #[clap(long, env = "TELEPROBE_TOKEN")]
        token: String,

        #[clap(long, env = "TELEPROBE_HOST")]
        host: String,

        #[clap(subcommand)]
        command: ClientCommand,
    },
}

#[derive(clap::Subcommand)]
enum LocalCommand {
    ListProbes,
    Run {
        /// ELF file to flash+run
        #[clap(long)]
        elf: String,

        #[clap(flatten)]
        probe: teleprobe::probe::Opts,
    },
}

#[derive(clap::Subcommand)]
enum ClientCommand {
    ListTargets,
    Run {
        #[clap(long)]
        target: String,
        /// ELF file to flash+run
        #[clap(long)]
        elf: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Local { command } => match command {
            LocalCommand::ListProbes => teleprobe::probe::list()?,
            LocalCommand::Run { elf, probe } => {
                configure_logger();
                let elf = std::fs::read(elf)?;
                let mut sess = teleprobe::probe::connect(probe)?;

                let opts = teleprobe::run::Options::default();
                teleprobe::run::run(&mut sess, &elf, opts)?
            }
        },
        Cli::Server { port } => {
            configure_logger();
            run_future(teleprobe::server::serve(port))?
        }
        Cli::Client { token, host, command } => {
            if !host.starts_with("http") {
                anyhow::bail!("Host must start with `http`.");
            }
            match command {
                ClientCommand::ListTargets => run_future(teleprobe::client::list_targets(&host, &token))?,
                ClientCommand::Run { elf, target } => run_future(teleprobe::client::run(&host, &token, &target, &elf))?,
            }
        }
    }

    Ok(())
}

fn configure_logger() {
    let mut builder = env_logger::Builder::new();
    if let Ok(s) = ::std::env::var("RUST_LOG") {
        builder.parse_filters(&s);
    } else {
        builder.filter_module("teleprobe", log::LevelFilter::Info);
        builder.filter_module("device", log::LevelFilter::Trace);
    }
    teleprobe::logging::thread_local_logger::init(Box::new(builder.build()));
}

fn run_future<F: Future>(future: F) -> F::Output {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(future)
}
