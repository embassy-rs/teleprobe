use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
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
    group: Option<String>,
}

impl ElfMetadata {
    fn from_elf(elf: &[u8]) -> anyhow::Result<(Self, Hasher)> {
        let mut target = None;
        let mut timeout = None;
        let mut group = None;

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

        if let Some(section) = obj_file.section_by_name(".teleprobe.group") {
            let data = section.data()?;
            if !data.is_empty() {
                match String::from_utf8(data.to_vec()) {
                    Ok(s) => group = Some(s),
                    Err(_) => warn!(".teleprobe.group contents are not a valid utf8 string."),
                }
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

        Ok((Self { target, timeout, group }, hasher))
    }
}

struct Member {
    path: PathBuf,
    target: String,
    elf: Vec<u8>,
    hash: String,
}

/// One run request: a single ELF, or all the ELFs of a group.
struct Job {
    group: Option<String>,
    members: Vec<Member>,
    /// Cache key. For a single ELF it's the ELF's hash, for a group it covers all members.
    hash: String,
    timeout: Option<u64>,
}

impl Job {
    fn log_name(&self, m: &Member) -> String {
        match &self.group {
            Some(group) => format!("{} {} (group {})", m.target, m.path.display(), group),
            None => format!("{} {}", m.target, m.path.display()),
        }
    }

    /// Sorted, so jobs on the same targets get the same key.
    fn targets(&self) -> Vec<String> {
        let targets: BTreeSet<_> = self.members.iter().map(|m| m.target.clone()).collect();
        targets.into_iter().collect()
    }
}

/// Turns ELFs into jobs. ELFs with the same group become one job, the others get one job each.
fn plan_jobs(
    files: Vec<(PathBuf, Vec<u8>)>,
    target_override: Option<&str>,
    timeout_override: Option<u64>,
) -> anyhow::Result<Vec<Job>> {
    let mut jobs: Vec<Job> = Vec::new();
    let mut groups: HashMap<String, usize> = HashMap::new();

    for (path, elf) in files {
        let (meta, mut hasher) = ElfMetadata::from_elf(&elf).with_context(|| format!("{}", path.display()))?;

        let target = target_override.map(str::to_string).or(meta.target).with_context(|| {
            format!(
                "{}: You have to either set --target, or embed it in the ELF using the `teleprobe-meta` crate.",
                path.display()
            )
        })?;

        hasher
            .update(target.as_bytes())
            .update(&meta.timeout.unwrap_or_default().to_le_bytes());
        let hash = hasher.finalize().to_string();

        let member = Member {
            path,
            target,
            elf,
            hash,
        };
        let new_job = |group| Job {
            group,
            members: Vec::new(),
            hash: String::new(),
            timeout: None,
        };
        let job = match meta.group {
            None => {
                jobs.push(new_job(None));
                jobs.last_mut().unwrap()
            }
            Some(group) => match groups.entry(group) {
                Entry::Occupied(e) => &mut jobs[*e.get()],
                Entry::Vacant(e) => {
                    jobs.push(new_job(Some(e.key().clone())));
                    e.insert(jobs.len() - 1);
                    jobs.last_mut().unwrap()
                }
            },
        };
        // The group gets the longest timeout of its members.
        job.timeout = job.timeout.max(meta.timeout);
        job.members.push(member);
    }

    for job in &mut jobs {
        if let Some(group) = &job.group {
            let mut seen: HashMap<&str, &PathBuf> = HashMap::new();
            for m in &job.members {
                if let Some(other) = seen.insert(&m.target, &m.path) {
                    bail!(
                        "Group {} has more than one ELF for target {}: {} and {}{}",
                        group,
                        m.target,
                        other.display(),
                        m.path.display(),
                        if target_override.is_some() {
                            ". Note that --target sets the target of every ELF."
                        } else {
                            ""
                        }
                    );
                }
            }
            if job.members.len() == 1 {
                warn!(
                    "Group {} has only one ELF: {}. Is the rest of the group missing?",
                    group,
                    job.members[0].path.display()
                );
            }
        }

        job.hash = match (&job.group, &job.members[..]) {
            (None, [m]) => m.hash.clone(),
            _ => {
                let mut hashes: Vec<&str> = job.members.iter().map(|m| m.hash.as_str()).collect();
                hashes.sort();
                let mut hasher = Hasher::new();
                for h in hashes {
                    hasher.update(h.as_bytes());
                }
                hasher.finalize().to_string()
            }
        };

        if timeout_override.is_some() {
            job.timeout = timeout_override;
        }
    }

    Ok(jobs)
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
        members: job
            .members
            .iter()
            .map(|m| api::RunMember {
                target: m.target.clone(),
                elf: m.elf.clone(),
            })
            .collect(),
    };

    // Names the job in the retry warnings: the group, or the single ELF.
    let label = match &job.group {
        Some(group) => format!("group {}", group),
        None => job.log_name(&job.members[0]),
    };
    let res = match send_run(client, creds, &req, job.timeout, &label).await {
        Ok(res) => res,
        Err(e) => {
            for m in &job.members {
                error!("=== {}: FAILED: {:#}", job.log_name(m), e);
            }
            return Err(());
        }
    };

    // The server answers in request order.
    for (m, r) in job.members.iter().zip(&res.members) {
        if r.ok {
            info!("=== {}: OK", job.log_name(m));
            if show_output {
                info!("{}", r.logs);
            }
        } else {
            let reason = r.reason.as_deref().unwrap_or("unknown");
            error!("=== {}: FAILED: {}", job.log_name(m), reason);
            error!("{}", r.logs);
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
            if res.members.len() != req.members.len() {
                bail!(
                    "server returned {} results for {} members",
                    res.members.len(),
                    req.members.len()
                );
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

    let files = files
        .into_iter()
        .map(|path| {
            let elf = std::fs::read(&path).with_context(|| format!("{}", path.display()))?;
            Ok((path, elf))
        })
        .collect::<anyhow::Result<_>>()?;
    let jobs = plan_jobs(files, cmd.target.as_deref(), cmd.timeout)?;

    let cache = load_cache(cmd.cache.clone());
    let job_count = jobs.len();
    // Keyed by the job's targets, so at most 2 requests are in flight per set of targets.
    let mut jobs_by_targets: HashMap<Vec<String>, Vec<Job>> = HashMap::new();
    let mut skipped_jobs: Vec<Job> = Vec::new();
    for job in jobs {
        if cache.contains(&job.hash) {
            skipped_jobs.push(job);
        } else {
            jobs_by_targets.entry(job.targets()).or_default().push(job);
        }
    }

    let target_count = jobs_by_targets.keys().flatten().collect::<HashSet<_>>().len();
    info!("Running {} jobs across {} targets...", job_count, target_count);

    for job in &skipped_jobs {
        for m in &job.members {
            info!("=== {}: OK (cached)", job.log_name(m));
        }
    }

    let client = reqwest::Client::new();

    let results: Vec<_> = stream::iter(jobs_by_targets)
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
    use object::{Architecture, BinaryFormat, Endianness, SectionKind, write};

    use super::*;

    /// Builds an ELF with the given code and teleprobe metadata.
    fn elf(code: &[u8], target: Option<&str>, timeout: Option<u32>, group: Option<&str>) -> Vec<u8> {
        let mut obj = write::Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
        let mut section = |name: &str, kind, data: &[u8]| {
            let id = obj.add_section(vec![], name.as_bytes().to_vec(), kind);
            obj.append_section_data(id, data, 1);
        };
        section(".text", SectionKind::Text, code);
        if let Some(target) = target {
            section(".teleprobe.target", SectionKind::Other, target.as_bytes());
        }
        if let Some(timeout) = timeout {
            section(".teleprobe.timeout", SectionKind::Other, &timeout.to_le_bytes());
        }
        if let Some(group) = group {
            section(".teleprobe.group", SectionKind::Other, group.as_bytes());
        }
        obj.write().unwrap()
    }

    fn file(name: &str, elf: Vec<u8>) -> (PathBuf, Vec<u8>) {
        (PathBuf::from(name), elf)
    }

    fn paths(job: &Job) -> Vec<String> {
        job.members.iter().map(|m| m.path.display().to_string()).collect()
    }

    #[test]
    fn metadata_is_read() {
        let (meta, _) = ElfMetadata::from_elf(&elf(b"code", Some("a"), Some(30), Some("pair"))).unwrap();
        assert_eq!(meta.target.as_deref(), Some("a"));
        assert_eq!(meta.timeout, Some(30));
        assert_eq!(meta.group.as_deref(), Some("pair"));

        let (meta, _) = ElfMetadata::from_elf(&elf(b"code", None, None, None)).unwrap();
        assert_eq!((meta.target, meta.timeout, meta.group), (None, None, None));
    }

    /// ELFs without a group run alone, and keep the cache key they had before groups existed.
    #[test]
    fn ungrouped_elfs_run_alone() {
        let one = elf(b"one", Some("a"), Some(30), None);
        let jobs = plan_jobs(
            vec![
                file("one", one.clone()),
                file("two", elf(b"two", Some("a"), None, None)),
            ],
            None,
            None,
        )
        .unwrap();
        assert_eq!(jobs.iter().map(paths).collect::<Vec<_>>(), [["one"], ["two"]]);
        assert_eq!(jobs[0].timeout, Some(30));
        assert_eq!(jobs[1].timeout, None);

        let (_, mut hasher) = ElfMetadata::from_elf(&one).unwrap();
        hasher.update(b"a").update(&30u64.to_le_bytes());
        assert_eq!(jobs[0].hash, hasher.finalize().to_string());
    }

    #[test]
    fn group_members_run_together() {
        let jobs = plan_jobs(
            vec![
                file("host", elf(b"host", Some("a"), Some(60), Some("pair"))),
                file("alone", elf(b"alone", Some("a"), None, None)),
                file("device", elf(b"device", Some("b"), Some(10), Some("pair"))),
            ],
            None,
            None,
        )
        .unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].group.as_deref(), Some("pair"));
        assert_eq!(paths(&jobs[0]), ["host", "device"]);
        assert_eq!(jobs[0].targets(), ["a", "b"]);
        // The group gets its members' longest timeout.
        assert_eq!(jobs[0].timeout, Some(60));
        assert_eq!(paths(&jobs[1]), ["alone"]);
    }

    #[test]
    fn group_hash() {
        let host = || file("host", elf(b"host", Some("a"), None, Some("pair")));
        let device = |code: &[u8]| file("device", elf(code, Some("b"), None, Some("pair")));
        let hash = |files| plan_jobs(files, None, None).unwrap().remove(0).hash;

        let h = hash(vec![host(), device(b"device")]);
        assert_eq!(h, hash(vec![device(b"device"), host()]), "depends on file order");
        assert_ne!(h, hash(vec![host(), device(b"changed")]), "ignores a member's change");
        assert_ne!(h, hash(vec![host()]), "ignores a missing member");
    }

    #[test]
    fn group_rejects_duplicate_targets() {
        let files = || {
            vec![
                file("host", elf(b"host", Some("a"), None, Some("pair"))),
                file("device", elf(b"device", Some("a"), None, Some("pair"))),
            ]
        };
        let err = plan_jobs(files(), None, None).err().unwrap().to_string();
        assert_eq!(err, "Group pair has more than one ELF for target a: host and device");

        let err = plan_jobs(files(), Some("a"), None).err().unwrap().to_string();
        assert!(
            err.ends_with("Note that --target sets the target of every ELF."),
            "{}",
            err
        );
    }

    #[test]
    fn group_of_one_is_allowed() {
        let jobs = plan_jobs(
            vec![file("host", elf(b"host", Some("a"), None, Some("pair")))],
            None,
            None,
        )
        .unwrap();
        assert_eq!(paths(&jobs[0]), ["host"]);
    }

    #[test]
    fn overrides() {
        let jobs = plan_jobs(
            vec![
                file("host", elf(b"host", Some("a"), Some(10), Some("pair"))),
                file("device", elf(b"device", Some("b"), Some(60), Some("pair"))),
            ],
            None,
            Some(5),
        )
        .unwrap();
        assert_eq!(jobs[0].timeout, Some(5));

        let jobs = plan_jobs(vec![file("one", elf(b"one", None, Some(10), None))], Some("x"), Some(5)).unwrap();
        assert_eq!(jobs[0].targets(), ["x"]);
        assert_eq!(jobs[0].timeout, Some(5));
    }

    #[test]
    fn missing_target() {
        let err = plan_jobs(vec![file("one", elf(b"one", None, None, None))], None, None)
            .err()
            .unwrap()
            .to_string();
        assert!(err.starts_with("one: You have to either set --target"), "{}", err);
    }
}
