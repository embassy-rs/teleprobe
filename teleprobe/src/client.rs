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

    /// Number of times to retry a reported failure, excluding unknown execution outcomes
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

enum JobFailure {
    Retryable,
    OutcomeUnknown,
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
            Err(JobFailure::Retryable) => {}
            Err(JobFailure::OutcomeUnknown) => break,
        }
    }

    Err(job)
}

/// Attempts for connection failures before dispatch. Independent of `--retries`.
const CONNECTION_ATTEMPTS: u32 = 5;

fn execution_client_builder() -> reqwest::ClientBuilder {
    Client::builder().redirect(reqwest::redirect::Policy::none())
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

async fn run_job_inner(client: &Client, creds: &Credentials, job: &Job, show_output: bool) -> Result<(), JobFailure> {
    let mut attempt = 1;
    let res = loop {
        match send_job(client, creds, job).await {
            Ok(res) => break Ok(res),
            Err(e) if e.is_connect() && attempt < CONNECTION_ATTEMPTS => {
                let delay = Duration::from_secs(1 << (attempt - 1));
                warn!(
                    "=== {} {}: HTTP request failed, retrying in {}s: {:#}",
                    job.target,
                    job.path.display(),
                    delay.as_secs(),
                    anyhow::Error::from(e)
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(e) => {
                let (failure, context) = if e.is_connect() {
                    (JobFailure::Retryable, "HTTP connection failed")
                } else {
                    (JobFailure::OutcomeUnknown, "execution outcome unknown; not retrying")
                };
                break Err((anyhow::Error::from(e).context(context), failure));
            }
        }
    };

    let (result, logs) = match res {
        Ok((status, logs)) if status.is_success() => (Ok(()), logs),
        Ok((status, logs)) if status.is_redirection() => (
            Err((
                anyhow::anyhow!("execution endpoint redirected; outcome unknown; not retrying"),
                JobFailure::OutcomeUnknown,
            )),
            logs,
        ),
        Ok((status, logs)) => (
            Err((
                anyhow::anyhow!(
                    "HTTP request failed with status code: {}: {}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
                JobFailure::Retryable,
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
        Err((e, failure)) => {
            error!("=== {} {}: FAILED: {:#}", job.target, job.path.display(), e);
            error!("{}", logs);
            Err(failure)
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

    let client = execution_client_builder().build()?;

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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::runtime::Builder;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::{Credentials, Job, execution_client_builder, run_job};

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nTest OK";
    const FAILED: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail";
    const TRUNCATED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncut";
    const REDIRECT: &[u8] = b"HTTP/1.1 303 See Other\r\nLocation: http://127.0.0.1:0/result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    struct HttpPeer {
        host: String,
        address: SocketAddr,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl HttpPeer {
        async fn start(responses: Vec<&'static [u8]>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let host = format!("http://{address}");
            let requests = Arc::new(AtomicUsize::new(0));
            let received = requests.clone();
            let task = tokio::spawn(async move {
                let mut responses = responses.into_iter();
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    loop {
                        let mut buffer = [0; 1024];
                        let length = stream.read(&mut buffer).await.unwrap();
                        assert_ne!(length, 0, "connection closed before complete request");
                        request.extend_from_slice(&buffer[..length]);
                        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                            let headers = std::str::from_utf8(&request[..end]).unwrap();
                            let content_length: usize = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(str::to_owned)
                                })
                                .unwrap()
                                .parse()
                                .unwrap();
                            if request.len() >= end + 4 + content_length {
                                assert!(headers.starts_with("POST /targets/test-board/run?timeout=7 HTTP/1.1\r\n"));
                                assert!(
                                    headers
                                        .to_ascii_lowercase()
                                        .contains("authorization: bearer test-token")
                                );
                                assert_eq!(&request[end + 4..], b"firmware");
                                break;
                            }
                        }
                    }
                    received.fetch_add(1, Ordering::SeqCst);
                    stream.write_all(responses.next().unwrap_or(OK)).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            Self {
                host,
                address,
                requests,
                task,
            }
        }
    }

    impl Drop for HttpPeer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn job() -> Job {
        Job {
            path: "firmware.elf".into(),
            target: "test-board".into(),
            elf: b"firmware".to_vec(),
            hash: "test-hash".into(),
            timeout: Some(7),
        }
    }

    async fn submit(peer: &HttpPeer, retries: Option<u8>) -> Result<Job, Job> {
        let client = execution_client_builder()
            .no_proxy()
            .timeout(TEST_TIMEOUT)
            .build()
            .unwrap();
        let credentials = Credentials {
            token: "test-token".into(),
            host: peer.host.clone(),
        };
        timeout(TEST_TIMEOUT, run_job(&client, &credentials, job(), false, retries))
            .await
            .unwrap()
    }

    #[test]
    fn connection_failure_before_dispatch_is_retried() {
        struct FirstResolutionFails {
            address: SocketAddr,
            resolutions: AtomicUsize,
        }

        impl reqwest::dns::Resolve for FirstResolutionFails {
            fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
                if self.resolutions.fetch_add(1, Ordering::SeqCst) == 0 {
                    Box::pin(async { Err(std::io::Error::other("DNS temporarily unavailable").into()) })
                } else {
                    let addresses: reqwest::dns::Addrs = Box::new(std::iter::once(self.address));
                    Box::pin(async { Ok(addresses) })
                }
            }
        }

        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let peer = HttpPeer::start(vec![OK]).await;
            let client = execution_client_builder()
                .no_proxy()
                .timeout(TEST_TIMEOUT)
                .dns_resolver(Arc::new(FirstResolutionFails {
                    address: peer.address,
                    resolutions: AtomicUsize::new(0),
                }))
                .build()
                .unwrap();
            let credentials = Credentials {
                token: "test-token".into(),
                host: format!("http://test.invalid:{}", peer.address.port()),
            };

            let result = timeout(TEST_TIMEOUT, run_job(&client, &credentials, job(), false, None))
                .await
                .unwrap();
            assert!(result.is_ok());
            assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn redirect_to_unreachable_destination_does_not_replay_post() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for retries in [None, Some(0), Some(2)] {
                let peer = HttpPeer::start(vec![REDIRECT]).await;
                assert!(submit(&peer, retries).await.is_err());
                assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
            }
        });
    }

    #[test]
    fn dropped_response_is_not_retried() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for retries in [None, Some(0), Some(2)] {
                let peer = HttpPeer::start(vec![b""]).await;
                assert!(submit(&peer, retries).await.is_err());
                assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
            }
        });
    }

    #[test]
    fn incomplete_response_body_is_not_retried() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for retries in [None, Some(0), Some(2)] {
                let peer = HttpPeer::start(vec![TRUNCATED]).await;
                assert!(submit(&peer, retries).await.is_err());
                assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
            }
        });
    }

    #[test]
    fn completed_http_failure_is_not_retried_by_default() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let peer = HttpPeer::start(vec![FAILED]).await;
            assert!(submit(&peer, None).await.is_err());
            assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn explicit_retries_apply_to_completed_http_failures() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let peer = HttpPeer::start(vec![FAILED, OK]).await;
            assert!(submit(&peer, Some(1)).await.is_ok());
            assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn successful_execution_is_not_repeated() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let peer = HttpPeer::start(vec![OK]).await;
            assert!(submit(&peer, Some(2)).await.is_ok());
            assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        });
    }
}
