use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::ops::Add;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use blake3::Hasher;
use futures::{StreamExt, stream};
use log::{error, info, warn};
use object::{Object, ObjectSection};
use parking_lot::Mutex;
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
    cooldown: &Cooldown,
) -> Result<Job, Job> {
    for _ in 0..retries.unwrap_or_default().add(1) {
        match run_job_inner(client, creds, &job, show_output, cooldown).await {
            Ok(_) => return Ok(job),
            _ => {}
        }
    }

    Err(job)
}

/// How many times a job is sent when communicating with the server fails (DNS, connect,
/// connection reset, proxy errors...), as opposed to the test failing. Independent of `--retries`.
const COMMUNICATION_ATTEMPTS: u32 = 5;

/// First retry happens after this long, doubled on every subsequent attempt,
/// capped at [`MAX_RETRY_DELAY`].
const BASE_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

fn retry_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    BASE_RETRY_DELAY.saturating_mul(1u32 << shift).min(MAX_RETRY_DELAY)
}

/// Statuses that can only come from a proxy or other middlebox between the client and the
/// teleprobe server: the server itself never returns them. They mean the request never
/// reached the runner (or its reply never made it back), so re-sending is safe.
///
/// Note what is deliberately *not* here: `400` is the server telling us the test ran and
/// failed (a chip failure must not be "recovered" by re-sending), and `500` is warp's
/// unhandled rejection (e.g. a bad auth token) — also not a communication problem.
fn is_communication_error(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

/// Shared by all jobs: the earliest time at which the next request may be sent.
///
/// When communication with the server fails, every failing job pushes this deadline
/// forward (taking the maximum, so all jobs agree on a single deadline), and every
/// job — including ones that have not failed yet — waits for it. This turns what would
/// be a thundering herd of independent retries against a struggling server into a
/// single trickle of requests. On top of that, each job waits its own jitter past the
/// deadline so the trickle does not re-synchronize into a new storm.
#[derive(Clone, Default)]
struct Cooldown {
    next: Arc<Mutex<Option<Instant>>>,
}

impl Cooldown {
    /// Push the shared deadline forward to at least `now + delay`.
    fn push(&self, delay: Duration) {
        let until = Instant::now() + delay;
        let mut next = self.next.lock();
        let current = *next;
        *next = Some(current.unwrap_or(until).max(until));
    }

    /// Wait until the shared deadline has passed, plus `jitter` on top, so that jobs
    /// released by the same deadline wake up spread out instead of all at once.
    async fn wait(&self, jitter: Duration) {
        loop {
            let next = *self.next.lock();
            let Some(until) = next else { return };
            let now = Instant::now();
            if now >= until + jitter {
                return;
            }
            tokio::time::sleep(until + jitter - now).await;
        }
    }
}

/// Deterministic jitter in `[0, span)` derived from the job's content hash and attempt
/// number: different jobs (and different attempts of the same job) get different values
/// without needing an RNG, so retries spread out instead of synchronizing.
fn job_jitter(hash: &str, attempt: u32, span: Duration) -> Duration {
    let mut hasher = Hasher::new();
    hasher.update(hash.as_bytes());
    hasher.update(&attempt.to_le_bytes());
    let value = u64::from_le_bytes(hasher.finalize().as_bytes()[..8].try_into().unwrap());
    let span_ns = span.as_nanos() as u64;
    if span_ns == 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(value % span_ns)
    }
}

async fn send_job(client: &Client, creds: &Credentials, job: &Job) -> Result<(StatusCode, String), reqwest::Error> {
    let res = client
        .post(format!("{}/targets/{}/run", creds.host, job.target))
        .query(&RunArgs { timeout: job.timeout })
        .body(job.elf.clone())
        .bearer_auth(&creds.token)
        .send()
        .await?;
    let status = res.status();
    let logs = res.text().await?;
    Ok((status, logs))
}

async fn run_job_inner(
    client: &Client,
    creds: &Credentials,
    job: &Job,
    show_output: bool,
    cooldown: &Cooldown,
) -> Result<(), ()> {
    let mut attempt = 1;
    let res = loop {
        // While the server (or the network) is failing, hold off — and spread jobs out
        // on wake-up so that recovering does not turn into a request storm.
        cooldown
            .wait(job_jitter(&job.hash, attempt, retry_delay(attempt)))
            .await;

        match send_job(client, creds, job).await {
            Ok((status, logs)) if status.is_success() => break Ok((status, logs)),
            Ok((status, _logs)) if is_communication_error(status) && attempt < COMMUNICATION_ATTEMPTS => {
                let delay = retry_delay(attempt);
                warn!(
                    "=== {} {}: HTTP {}, retrying in {}s (attempt {}/{}): {}",
                    job.target,
                    job.path.display(),
                    status.as_u16(),
                    delay.as_secs(),
                    attempt + 1,
                    COMMUNICATION_ATTEMPTS,
                    status.canonical_reason().unwrap_or("unknown")
                );
                cooldown.push(delay);
                attempt += 1;
            }
            Ok(res) => break Ok(res),
            Err(e) if attempt < COMMUNICATION_ATTEMPTS => {
                let delay = retry_delay(attempt);
                warn!(
                    "=== {} {}: HTTP request failed, retrying in {}s (attempt {}/{}): {:#}",
                    job.target,
                    job.path.display(),
                    delay.as_secs(),
                    attempt + 1,
                    COMMUNICATION_ATTEMPTS,
                    anyhow::Error::from(e)
                );
                cooldown.push(delay);
                attempt += 1;
            }
            Err(e) => break Err(anyhow::Error::from(e).context("HTTP request failed")),
        }
    };

    let (result, logs) = match res {
        Ok((status, logs)) if status.is_success() => (Ok(()), logs),
        Ok((status, logs)) => (
            Err(anyhow::anyhow!(
                "HTTP request failed with status code: {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("unknown")
            )),
            logs,
        ),
        Err(e) => (Err(e), String::new()),
    };

    match result {
        Ok(()) => {
            info!("=== {} {}: OK", job.target, job.path.display());
            if show_output {
                info!("{}", logs);
            }
            Ok(())
        }
        Err(e) => {
            error!("=== {} {}: FAILED: {:#}", job.target, job.path.display(), e);
            error!("{}", logs);
            Err(())
        }
    }
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
    let cooldown = Cooldown::default();

    let results: Vec<_> = stream::iter(jobs_by_target)
        .flat_map_unordered(None, |(_, jobs)| {
            let client = &client;
            let cooldown = &cooldown;
            stream::iter(jobs)
                .map(move |job| run_job(client, creds, job, cmd.show_output, cmd.retries, cooldown))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_proxy_statuses_are_communication_errors() {
        // statuses a middlebox can produce: retry these.
        for code in [408, 429, 502, 503, 504] {
            assert!(is_communication_error(StatusCode::from_u16(code).unwrap()), "{code}");
        }

        // 200: test passed. 400: the server ran the test and the chip failed - never
        // "recover" by re-sending. 401/404/500: config or server bugs, not the network.
        for code in [200, 400, 401, 404, 500] {
            assert!(!is_communication_error(StatusCode::from_u16(code).unwrap()), "{code}");
        }
    }

    #[test]
    fn retry_delay_grows_and_is_capped() {
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(4), Duration::from_secs(8));
        assert_eq!(retry_delay(5), Duration::from_secs(16));
        assert_eq!(retry_delay(6), MAX_RETRY_DELAY);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }

    #[test]
    fn job_jitter_is_deterministic_and_in_bounds() {
        let span = Duration::from_secs(8);
        let a = job_jitter("hash-a", 1, span);
        assert_eq!(a, job_jitter("hash-a", 1, span));
        assert!(a < span);
        assert_eq!(job_jitter("hash-a", 1, Duration::ZERO), Duration::ZERO);

        // different jobs and different attempts spread out over the span.
        let mut seen = HashSet::new();
        for i in 0..16 {
            let j = job_jitter(&format!("hash-{i}"), 1, span);
            assert!(j < span);
            seen.insert(j);
        }
        assert!(seen.len() > 1, "jitter should differ between jobs");
    }

    #[test]
    fn cooldown_takes_the_latest_deadline() {
        let cooldown = Cooldown::default();
        assert!(cooldown.next.lock().is_none());

        cooldown.push(Duration::from_secs(10));
        let first = *cooldown.next.lock();
        assert!(first.is_some());

        // a shorter delay must not pull the deadline back...
        cooldown.push(Duration::from_millis(1));
        assert_eq!(*cooldown.next.lock(), first);

        // ...but a longer one pushes it forward.
        cooldown.push(Duration::from_secs(60));
        assert!(*cooldown.next.lock() > first);
    }
}
