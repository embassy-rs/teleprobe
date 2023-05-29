use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{bail, Context};
use futures::{stream, StreamExt};
use log::{error, info};
use object::{Object, ObjectSection};
use reqwest::Client;
use walkdir::WalkDir;

use crate::api;

#[derive(clap::Parser)]
pub struct Command {
    #[clap(flatten)]
    credentials: Credentials,

    #[clap(subcommand)]
    cmd: Subcommand,
}

#[derive(clap::Parser)]
struct Credentials {
    #[clap(long, env = "TELEPROBE_TOKEN")]
    token: String,

    #[clap(long, env = "TELEPROBE_HOST")]
    host: String,
}

#[derive(clap::Parser)]
enum Subcommand {
    ListTargets,
    Run(RunCommand),
}

#[derive(clap::Parser)]
pub struct RunCommand {
    /// Teleprobe target to run the ELFs in.
    /// If not specified, it will be autodetected based on the value of the `.teleprobe.target` section from the ELF.
    #[clap(long)]
    target: Option<String>,

    /// ELF files to flash+run
    files: Vec<String>,

    /// Recursively run all files under the given directories
    #[clap(short)]
    recursive: bool,

    /// Show output logs for successes, not just failures.
    #[clap(short)]
    show_output: bool,
}

pub async fn main(cmd: Command) -> anyhow::Result<()> {
    if !cmd.credentials.host.starts_with("http") {
        anyhow::bail!("Host must start with `http`.");
    }

    match cmd.cmd {
        Subcommand::ListTargets => list_targets(&cmd.credentials).await,
        Subcommand::Run(scmd) => run(&cmd.credentials, scmd).await,
    }
}

fn detect_target(elf: &[u8]) -> anyhow::Result<String> {
    let obj_file = object::File::parse(elf)?;
    let Some(section) = obj_file.section_by_name(".teleprobe.target") else {
        bail!(".teleprobe.target section not available")
    };
    let data = section.data()?;
    if data.is_empty() {
        bail!(".teleprobe.target section is empty")
    }

    Ok(String::from_utf8(data.to_vec()).context(".teleprobe.target contents are not a valid utf8 string.")?)
}

struct Job {
    path: PathBuf,
    target: String,
    elf: Vec<u8>,
}

async fn run_job(client: &Client, creds: &Credentials, job: Job, show_output: bool) -> bool {
    let res = client
        .post(format!("{}/targets/{}/run", creds.host, job.target))
        .body(job.elf)
        .bearer_auth(&creds.token)
        .send()
        .await;

    let mut logs = String::new();
    let result = match res.context("HTTP request failed") {
        Ok(res) => {
            let status = res.status();
            logs = res.text().await.unwrap_or_else(|_| "empty".to_string());
            if status.is_success() {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "HTTP request failed with status code: {}: {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("unknown")
                ))
            }
        }
        Err(e) => Err(e),
    };

    match result {
        Ok(()) => {
            info!("=== {} {}: OK", job.target, job.path.display());
            if show_output {
                info!("{}", logs);
            }
            true
        }
        Err(e) => {
            error!("=== {} {}: FAILED: {}", job.target, job.path.display(), e);
            error!("{}", logs);
            false
        }
    }
}

async fn run(creds: &Credentials, cmd: RunCommand) -> anyhow::Result<()> {
    let files = if cmd.recursive {
        let mut files = Vec::new();

        for f in cmd.files {
            for entry in WalkDir::new(f).follow_links(true) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    files.push(entry.path().to_owned())
                }
            }
        }

        files
    } else {
        cmd.files.iter().map(|f| f.into()).collect()
    };

    let job_count = files.len();
    let mut jobs_by_target: HashMap<String, Vec<Job>> = HashMap::new();

    for path in files {
        let elf: Vec<u8> = std::fs::read(&path)?;

        let target = match cmd.target.clone() {
            Some(t) => t,
            None => detect_target(&elf)?,
        };

        jobs_by_target
            .entry(target.clone())
            .or_default()
            .push(Job { path, target, elf });
    }

    info!("Running {} jobs across {} targets...", job_count, jobs_by_target.len());

    let client = reqwest::Client::new();

    let results: Vec<_> = stream::iter(jobs_by_target)
        .flat_map_unordered(None, |(_, jobs)| {
            let client = &client;
            stream::iter(jobs)
                .map(move |job| run_job(client, creds, job, cmd.show_output))
                .buffer_unordered(2)
        })
        .collect()
        .await;

    let mut succeeded = 0;
    let mut failed = 0;
    for r in results {
        match r {
            true => succeeded += 1,
            false => failed += 1,
        }
    }

    if failed != 0 {
        log::error!("{} succeeded, {} failed :(", succeeded, failed);
        bail!("test failed")
    } else {
        log::info!("all {} succeeded!", succeeded);
        Ok(())
    }
}

async fn list_targets(creds: &Credentials) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/targets", creds.host))
        .bearer_auth(&creds.token)
        .send()
        .await?;

    if res.status().is_success() {
        println!("Teleprobe server supports the following targets:");
        println!("{:20} {:14} {:6}", "name", "chip", "up");

        let text = res.text().await?;
        let targets: api::TargetList = serde_json::from_str(&text)?;
        let targets: Vec<String> = targets
            .targets
            .iter()
            .map(|target| format!("{:20} {:14} {:6}", target.name, target.chip, target.up))
            .collect();
        println!("{}", targets.join("\n"));
        Ok(())
    } else {
        println!("Error getting list of Teleprobe server targets");
        println!(
            "status code: {}: {}",
            res.status().as_u16(),
            res.status().canonical_reason().unwrap_or("unknown")
        );
        println!(
            "response body: {}",
            res.text().await.unwrap_or_else(|_| "empty".to_string())
        );
        bail!("Running failed!");
    }
}
