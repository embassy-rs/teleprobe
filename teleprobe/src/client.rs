use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::ops::Add;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use blake3::Hasher;
use futures::{StreamExt, stream};
use log::{error, info, warn};
use object::{Object, ObjectSection};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
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

    /// Cache file to avoid re-running binaries.
    /// If not specified, all binaries will be run.
    /// If specified, only the binaries that have changed will be run.
    #[clap(long, env = "TELEPROBE_CACHE")]
    cache: Option<String>,

    /// ELF files to flash+run
    files: Vec<String>,

    /// Number of times to retry a failure
    #[clap(long)]
    retries: Option<u8>,

    /// Recursively run all files under the given directories
    #[clap(short)]
    recursive: bool,

    /// Show output logs for successes, not just failures.
    #[clap(short)]
    show_output: bool,

    /// Override job timeout
    #[clap(short)]
    timeout: Option<u64>,
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

#[derive(Serialize, Deserialize, Default)]
struct Cache {
    /// A map of file checksums that have passed the test.
    files: HashSet<String>,
}

impl Cache {
    pub fn contains(&self, hash: &String) -> bool {
        self.files.contains(hash)
    }

    pub fn insert(&mut self, hash: String) -> bool {
        self.files.insert(hash)
    }
}

#[derive(Clone, Debug)]
struct ElfMetadata {
    target: Option<String>,
    timeout: Option<u64>,
}

impl ElfMetadata {
    fn from_elf(elf: &[u8]) -> anyhow::Result<(Self, Hasher)> {
        let mut target = None;
        let mut timeout = None;

        let obj_file = object::File::parse(elf)?;

        if let Some(section) = obj_file.section_by_name(".teleprobe.target") {
            let data = section.data()?;
            if !data.is_empty() {
                match String::from_utf8(data.to_vec()) {
                    Ok(s) => target = Some(s),
                    Err(_) => warn!(".teleprobe.target contents are not a valid utf8 string."),
                }
            }
        }

        if let Some(section) = obj_file.section_by_name(".teleprobe.timeout") {
            let data = section.data()?;
            if data.len() == 4 {
                timeout = Some(u32::from_le_bytes(data.try_into().unwrap()) as u64)
            } else {
                warn!(".teleprobe.timeout contents are not a valid u32.")
            }
        }

        let mut hasher = Hasher::new();
        for section in &mut obj_file.sections() {
            let section_name = match section.name() {
                Ok(name) => name,
                _ => continue,
            };

            if section_name.is_empty() || section_name.starts_with(".debug_") {
                continue;
            }

            let section_data = match section.data() {
                Ok(data) => data,
                _ => continue,
            };

            let section_address = section.address();

            hasher
                .update(section_name.as_bytes())
                .update(section_data)
                .update(&section_address.to_le_bytes());
        }

        Ok((Self { target, timeout }, hasher))
    }
}

struct Job {
    path: PathBuf,
    target: String,
    elf: Vec<u8>,
    hash: String,
    timeout: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct RunArgs {
    #[serde(default)]
    timeout: Option<u64>,
}

async fn run_job(
    client: &Client,
    creds: &Credentials,
    job: Job,
    show_output: bool,
    retries: Option<u8>,
) -> Result<Job, Job> {
    for _ in 0..retries.unwrap_or_default().add(1) {
        match run_job_inner(client, creds, &job, show_output).await {
            Ok(_) => return Ok(job),
            _ => {}
        }
    }

    Err(job)
}

async fn run_job_inner(client: &Client, creds: &Credentials, job: &Job, show_output: bool) -> Result<(), ()> {
    let req = api::RunRequest {
        members: vec![api::RunMember {
            target: job.target.clone(),
            elf: job.elf.clone(),
        }],
    };

    let label = format!("{} {}", job.target, job.path.display());
    let res = match send_run(client, creds, &req, job.timeout, &label).await {
        Ok(res) => res,
        Err(e) => {
            error!("=== {}: FAILED: {:#}", label, e);
            return Err(());
        }
    };

    for m in &res.members {
        if m.ok {
            info!("=== {} {}: OK", m.target, job.path.display());
            if show_output {
                info!("{}", m.logs);
            }
        } else {
            let reason = m.reason.as_deref().unwrap_or("unknown");
            error!("=== {} {}: FAILED: {}", m.target, job.path.display(), reason);
            error!("{}", m.logs);
        }
    }

    if res.ok { Ok(()) } else { Err(()) }
}

/// How many times a run request is sent when the HTTP request itself fails (DNS, connect, connection reset...),
/// as opposed to the test failing. Independent of `--retries`.
const CONNECTION_ATTEMPTS: u32 = 5;

async fn post_run(
    client: &Client,
    creds: &Credentials,
    req: &api::RunRequest,
    timeout: Option<u64>,
) -> Result<(StatusCode, String), reqwest::Error> {
    let res = client
        .post(format!("{}/targets/run", creds.host))
        .query(&RunArgs { timeout })
        .json(req)
        .bearer_auth(&creds.token)
        .send()
        .await?;
    let status = res.status();
    let body = res.text().await?;
    Ok((status, body))
}

/// Sends a run request. Returns an error if the run didn't happen, for example because the request was invalid.
/// `label` names the job in the retry warnings.
async fn send_run(
    client: &Client,
    creds: &Credentials,
    req: &api::RunRequest,
    timeout: Option<u64>,
    label: &str,
) -> anyhow::Result<api::RunResponse> {
    let mut attempt = 1;
    let (status, body) = loop {
        match post_run(client, creds, req, timeout).await {
            Ok(res) => break res,
            Err(e) if attempt < CONNECTION_ATTEMPTS => {
                let delay = Duration::from_secs(1 << (attempt - 1));
                warn!(
                    "=== {}: HTTP request failed, retrying in {}s: {:#}",
                    label,
                    delay.as_secs(),
                    anyhow::Error::from(e)
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => return Err(anyhow::Error::from(e).context("HTTP request failed")),
        }
    };

    // Runs answer 200 or 400 with a JSON body. Anything else, or a body that isn't JSON, is a request error.
    if status == StatusCode::OK || status == StatusCode::BAD_REQUEST {
        if let Ok(res) = serde_json::from_str::<api::RunResponse>(&body) {
            if res.ok && status != StatusCode::OK {
                bail!("server returned status {} for a passing run", status.as_u16());
            }
            return Ok(res);
        }
    }

    bail!(
        "HTTP request failed with status code: {}: {}: {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("unknown"),
        body
    )
}

fn load_cache(cache: Option<String>) -> Cache {
    let cache = match cache {
        Some(cache) => cache,
        _ => return Cache::default(),
    };

    let cache_file = match File::open(cache) {
        Ok(cache_file) => cache_file,
        _ => return Cache::default(),
    };

    match serde_json::from_reader(&cache_file) {
        Ok(cache) => cache,
        _ => Cache::default(),
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

    let cache = load_cache(cmd.cache.clone());
    let job_count = files.len();
    let mut jobs_by_target: HashMap<String, Vec<Job>> = HashMap::new();
    let mut skipped_jobs: Vec<Job> = Vec::new();

    for path in files {
        let elf: Vec<u8> = std::fs::read(&path)?;
        let (meta, mut hasher) = ElfMetadata::from_elf(&elf)?;

        let target = cmd
            .target
            .clone()
            .or(meta.target)
            .context("You have to either set --target, or embed it in the ELF using the `teleprobe-meta` crate.")?;

        hasher
            .update(target.as_bytes())
            .update(&meta.timeout.unwrap_or_default().to_le_bytes());

        let hash = hasher.finalize().to_string();
        // Override timeout if requested
        let timeout = match cmd.timeout {
            Some(_) => cmd.timeout,
            None => meta.timeout,
        };

        let jobs = if cache.contains(&hash) {
            &mut skipped_jobs
        } else {
            jobs_by_target.entry(target.clone()).or_default()
        };

        jobs.push(Job {
            path,
            target,
            elf,
            hash,
            timeout,
        });
    }

    info!("Running {} jobs across {} targets...", job_count, jobs_by_target.len());

    for job in &skipped_jobs {
        info!("=== {} {}: OK (cached)", job.target, job.path.display());
    }

    let client = reqwest::Client::new();

    let results: Vec<_> = stream::iter(jobs_by_target)
        .flat_map_unordered(None, |(_, jobs)| {
            let client = &client;
            stream::iter(jobs)
                .map(move |job| run_job(client, creds, job, cmd.show_output, cmd.retries))
                .buffer_unordered(2)
        })
        .collect()
        .await;

    let mut succeeded = skipped_jobs.len();
    let mut failed = 0usize;
    let mut cache = Cache {
        files: skipped_jobs.into_iter().map(|job| job.hash).collect(),
    };

    for r in results {
        match r {
            Ok(job) => {
                cache.insert(job.hash.clone());

                succeeded += 1
            }
            Err(_) => failed += 1,
        }
    }

    cmd.cache.map(|cache_path| {
        let cache_file = match File::create(&cache_path) {
            Ok(cache_file) => cache_file,
            _ => return,
        };

        match serde_json::to_writer(cache_file, &cache) {
            Ok(_) => println!("saved cache to {}", &cache_path),
            Err(_) => println!("failed to saved cache to {}", &cache_path),
        };

        // I assume the file is closed when it's dropped here
    });

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
