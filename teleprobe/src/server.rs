use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::bail;
use bytes::Bytes;
use futures::future::join_all;
use log::{error, info};
use parking_lot::Mutex;
use probe_rs::probe::list::Lister;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use warp::http::StatusCode;
use warp::reply::{Response, html, json, with_status};
use warp::{Filter, Rejection, Reply};

use crate::auth::oidc;
use crate::auth::oidc::Client;
use crate::config::{Auth, Config, OidcAuthRule, Target};
#[cfg(target_os = "linux")]
use crate::probe::power_enable;
use crate::scheduler::{Grant, Queue};
use crate::util::ondrop::OnDrop;
use crate::{api, probe, run};

/// Runs firmware on a target. Abstracted so the server can be tested without hardware.
/// A run must fail soon after `cancel` is set.
trait Runner: Send + Sync {
    fn run(&self, elf: &[u8], probe: &probe::Opts, timeout: Duration, cancel: Arc<AtomicBool>) -> anyhow::Result<()>;
}

struct ProbeRunner;

impl Runner for ProbeRunner {
    fn run(&self, elf: &[u8], probe: &probe::Opts, timeout: Duration, cancel: Arc<AtomicBool>) -> anyhow::Result<()> {
        // Don't bother connecting and flashing if another member already failed.
        if cancel.load(Ordering::Relaxed) {
            bail!("Cancelled");
        }
        let mut sess = probe::connect(probe)?;

        let opts = run::Options {
            deadline: Some(Instant::now() + timeout),
            cancel: Some(cancel),
            ..Default::default()
        };
        run::run(&mut sess, elf, opts)?;

        Ok(())
    }
}

/// Runs one member, and returns why it failed, if it did, and its logs. A failure cancels the rest of the group.
async fn run_with_log_capture(
    runner: Arc<dyn Runner>,
    grant: Arc<Grant>,
    cancel: Arc<AtomicBool>,
    elf: Vec<u8>,
    probe: probe::Opts,
    timeout: Duration,
) -> (Result<(), String>, String) {
    let (res, entries) = spawn_blocking(move || {
        // The grant lives in the blocking tasks, not in the request handler. If the client
        // disconnects, the handler is dropped but the runs continue, and must keep their targets.
        // It's shared by all members, so the group's targets are freed when the last one finishes.
        let _grant = grant;
        crate::logutil::with_capture(|| {
            runner.run(&elf, &probe, timeout, cancel.clone()).map_err(|e| {
                error!("Run failed: {:?}", e);
                cancel.store(true, Ordering::Relaxed);
                format!("{:#}", e)
            })
        })
    })
    .await
    .unwrap();

    let mut logs = String::new();
    for entry in entries {
        writeln!(&mut logs, "{} - {}", entry.level, entry.message).unwrap();
    }
    (res, logs)
}

macro_rules! reject {
    (StatusCode::$code:ident, $($x:tt)*) => {
        return Ok(with_status(
            format!($($x)*).as_bytes().to_vec(),
            StatusCode::$code,
        )
        .into_response())
    };
    ($($x:tt)*) => {
        reject!(StatusCode::BAD_REQUEST, $($x)*)
    };
}

fn check_auth_token(oidc_client: Option<&Client>, token: &str, auth: &Auth) -> Result<(), anyhow::Error> {
    match auth {
        Auth::Token(auth) => {
            if token != auth.token {
                bail!("Incorrect token")
            }
            Ok(())
        }
        Auth::Oidc(auth) => {
            if let Some(client) = &oidc_client {
                let claims: HashMap<String, serde_json::Value> = match client.validate_token(token) {
                    Ok(x) => x,
                    Err(e) => bail!("Bad token: {}", e),
                };

                let claims: HashMap<String, String> = claims
                    .into_iter()
                    .filter_map(|(k, v)| match v {
                        serde_json::Value::String(s) => Some((k, s)),
                        _ => None,
                    })
                    .collect();

                if !auth
                    .rules
                    .iter()
                    .any(|r: &OidcAuthRule| r.claims.iter().all(|(k, v)| claims.get(k) == Some(v)))
                {
                    bail!("No oidc claims rule matched");
                }

                Ok(())
            } else {
                bail!("Attempted to use OIDC auth when OIDC was not configured.")
            }
        }
    }
}

// Warp doesn't support UNAUTHORIZED in rejects yet
#[derive(Debug)]
struct BadAuthHeaderFormat;

impl warp::reject::Reject for BadAuthHeaderFormat {}

#[derive(Debug)]
struct Unauthorized;

impl warp::reject::Reject for Unauthorized {}

async fn check_auth(auth_header: String, cx: Arc<Mutex<Context>>) -> Result<(), Rejection> {
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return Err(warp::reject::custom(BadAuthHeaderFormat)),
    };

    let mut found = false;

    let context = cx.lock();
    for (i, auth) in context.config.auths.iter().enumerate() {
        match check_auth_token(context.oidc_client.as_ref(), token, auth) {
            Ok(()) => {
                found = true;
                info!("Auth method {} #{} succeeded.", auth.to_string(), i);
                break;
            }
            Err(e) => {
                info!("Auth method {} #{} failed: {}", auth.to_string(), i, e)
            }
        }
    }

    if !found {
        return Err(warp::reject::custom(Unauthorized));
    }

    Ok(())
}

fn check_auth_filter(cx: Arc<Mutex<Context>>) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let with_context = warp::any().map(move || cx.clone());
    warp::header("Authorization")
        .and(with_context)
        .and_then(check_auth)
        .untuple_one()
}

#[derive(Deserialize, Serialize)]
struct RunArgs {
    #[serde(default)]
    timeout: Option<u64>,
}

fn probe_opts(target: &Target) -> probe::Opts {
    probe::Opts {
        chip: target.chip.clone(),
        connect_under_reset: target.connect_under_reset,
        probe: Some(target.probe.clone()),
        speed: target.speed,
        power_reset: target.power_reset,
        cycle_delay_seconds: target.cycle_delay_seconds,
        max_settle_time_millis: target.max_settle_time_millis,
        protocol: None,
    }
}

async fn handle_run(args: RunArgs, body: Bytes, cx: Arc<Mutex<Context>>) -> Result<Response, Rejection> {
    let req: api::RunRequest = match serde_json::from_slice(&body) {
        Ok(x) => x,
        Err(e) => reject!("Invalid request: {}", e),
    };
    if req.members.is_empty() {
        reject!("Request has no members");
    }

    let (members, timeout, queue, runner) = {
        let context = cx.lock();
        let config = &context.config;

        let mut seen = HashSet::new();
        let mut members = Vec::new();
        for m in req.members {
            if !seen.insert(m.target.clone()) {
                reject!("Duplicate target: {}", m.target);
            }
            match config.targets.iter().find(|t| t.name == m.target) {
                Some(target) => members.push((target.clone(), m.elf)),
                None => reject!(StatusCode::NOT_FOUND, "Target not found: {}", m.target),
            }
        }

        let timeout = Duration::from_secs(args.timeout.unwrap_or(config.default_timeout).min(config.max_timeout));
        (members, timeout, context.queue.clone(), context.runner.clone())
    };

    let grant = queue
        .acquire(members.iter().map(|(t, _)| t.name.clone()).collect())
        .await;
    let grant = Arc::new(grant);

    // If the client disconnects, this handler is dropped, and nobody is waiting for the result.
    // Cancel the runs so the targets are freed early. After a normal finish, this does nothing.
    let cancel = Arc::new(AtomicBool::new(false));
    let _cancel_on_drop = OnDrop::new({
        let cancel = cancel.clone();
        move || cancel.store(true, Ordering::Relaxed)
    });

    let runs = members.into_iter().map(|(target, elf)| {
        let run = run_with_log_capture(
            runner.clone(),
            grant.clone(),
            cancel.clone(),
            elf,
            probe_opts(&target),
            timeout,
        );
        async move {
            let (res, logs) = run.await;
            api::MemberResult {
                target: target.name,
                ok: res.is_ok(),
                reason: res.err(),
                logs,
            }
        }
    });
    let members = join_all(runs).await;

    let ok = members.iter().all(|m| m.ok);
    let status = if ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };
    Ok(with_status(json(&api::RunResponse { ok, members }), status).into_response())
}

fn targets(cx: Arc<Mutex<Context>>) -> api::TargetList {
    let targets = cx.lock().config.targets.clone();
    let mut res = Vec::new();
    let up_probes = Lister::new().list_all();

    for target in targets {
        let is_up = up_probes.iter().any(|probe| {
            probe.vendor_id == target.probe.vendor_id
                && probe.product_id == target.probe.product_id
                && target
                    .probe
                    .serial_number
                    .as_ref()
                    .map(|s| Some(s) == probe.serial_number.as_ref())
                    .unwrap_or(true)
        });
        res.push(api::Target {
            name: target.name,
            chip: target.chip,
            probe: target.probe,
            connect_under_reset: target.connect_under_reset,
            speed: target.speed,
            up: is_up,
            power_reset: target.power_reset,
            cycle_delay_seconds: target.cycle_delay_seconds,
            max_settle_time_millis: target.max_settle_time_millis,
        });
    }

    api::TargetList { targets: res }
}

async fn handle_list_targets(cx: Arc<Mutex<Context>>) -> Result<impl Reply, Rejection> {
    let targets = targets(cx);

    Ok(with_status(
        // NOTE (unwrap): error in this call is caused by programmer error and should never be caused by the user data
        serde_json::to_vec_pretty(&targets).unwrap(),
        StatusCode::OK,
    ))
}

async fn handle_home(cx: Arc<Mutex<Context>>) -> Result<impl Reply, Rejection> {
    let targets = targets(cx);

    let mut res = String::new();

    write!(&mut res, "<html>").unwrap();
    write!(&mut res, "<head><title>Teleprobe Status</title></head>").unwrap();
    write!(&mut res, "<body>").unwrap();
    write!(&mut res, "<h1>Teleprobe Status</h1>").unwrap();
    write!(&mut res, "<table>").unwrap();
    write!(&mut res, "<tr>").unwrap();
    write!(&mut res, "<th>Name</th>").unwrap();
    write!(&mut res, "<th>Chip</th>").unwrap();
    write!(&mut res, "<th>Up</th>").unwrap();
    write!(&mut res, "</tr>").unwrap();

    for target in targets.targets {
        write!(&mut res, "<tr>").unwrap();
        write!(&mut res, "<td>{}</td>", target.name).unwrap();
        write!(&mut res, "<td>{}</td>", target.chip).unwrap();
        write!(&mut res, "<td>{}</td>", target.up).unwrap();
        write!(&mut res, "</tr>").unwrap();
    }
    write!(&mut res, "</table>").unwrap();
    write!(
        &mut res,
        "<br><br> -- <a href=\"https://github.com/embassy-rs/teleprobe\">Teleprobe</a> version {}",
        crate::meta::LONG_VERSION
    )
    .unwrap();
    write!(&mut res, "</body></html>").unwrap();

    Ok(html(res))
}

#[derive(Clone)]
struct Context {
    oidc_client: Option<oidc::Client>,
    config: Config,
    queue: Arc<Queue>,
    runner: Arc<dyn Runner>,
}

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let config = fs::read("config.yaml")?;
    let config: Config = serde_yaml::from_slice(&config)?;

    #[cfg(target_os = "linux")]
    if let Err(e) = power_enable().await {
        log::warn!("failed to enable power to all hubs: {:?}", e);
    }

    // TODO support none or multiple oidc issuers.
    let oidc_client = match config.auths.iter().find_map(|a| match a {
        Auth::Oidc(o) => Some(o),
        _ => None,
    }) {
        Some(auth) => Some(oidc::Client::new_autodiscover(&auth.issuer).await.unwrap()),
        None => None,
    };

    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context {
        oidc_client,
        queue: Queue::new(Duration::from_secs(config.reserve_after_secs)),
        config,
        runner: Arc::new(ProbeRunner),
    }));

    info!("Listening on :{}", port);
    warp::serve(routes(context)).run(([0, 0, 0, 0], port)).await;

    Ok(())
}

fn routes(context: Arc<Mutex<Context>>) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let target_run = warp::path!("targets" / "run")
        .and(warp::post())
        .and(check_auth_filter(context.clone()))
        .and(warp::query())
        .and(warp::body::bytes())
        .and(with_val(context.clone()))
        .and_then(handle_run);

    let list_targets = warp::path!("targets")
        .and(warp::get())
        .and(check_auth_filter(context.clone()))
        .and(with_val(context.clone()))
        .and_then(handle_list_targets);

    let home = warp::path!()
        .and(warp::get())
        .and(with_val(context.clone()))
        .and_then(handle_home);

    target_run.or(list_targets).or(home)
}

fn with_val<T: Clone + Send>(val: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const CONFIG: &str = "
auths:
  - !token
      token: secret
targets:
  - name: a
    chip: chip-a
    probe: 1234:0001
  - name: b
    chip: chip-b
    probe: 1234:0002
";

    /// Like a real board, a cancelled run takes a while to stop, because the core is halted and its state dumped.
    const HALT_TIME: Duration = Duration::from_millis(100);

    /// Stands in for a board. The "ELF" is a script: `ok`, `fail` or `sleep:<ms>`. Sleeps can be cancelled.
    #[derive(Default)]
    struct FakeRunner {
        /// Number of runs currently in progress, per chip.
        running: Mutex<HashMap<String, usize>>,
        /// Number of times a run started on a chip that was already running.
        overlaps: AtomicUsize,
        max_concurrent: AtomicUsize,
        timeouts: Mutex<Vec<Duration>>,
        cancelled: AtomicUsize,
    }

    impl FakeRunner {
        fn is_running(&self, chip: &str) -> bool {
            self.running.lock().get(chip).copied().unwrap_or(0) > 0
        }

        fn script(&self, elf: &[u8], cancel: &AtomicBool) -> anyhow::Result<()> {
            match std::str::from_utf8(elf)? {
                "ok" => info!("fake run ok"),
                "fail" => bail!("fake failure"),
                s => match s.strip_prefix("sleep:") {
                    Some(ms) => {
                        let end = Instant::now() + Duration::from_millis(ms.parse()?);
                        while Instant::now() < end {
                            if cancel.load(Ordering::Relaxed) {
                                self.cancelled.fetch_add(1, Ordering::SeqCst);
                                std::thread::sleep(HALT_TIME);
                                bail!("Cancelled");
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                    None => bail!("unknown fake script: {}", s),
                },
            }
            Ok(())
        }
    }

    impl Runner for FakeRunner {
        fn run(
            &self,
            elf: &[u8],
            probe: &probe::Opts,
            timeout: Duration,
            cancel: Arc<AtomicBool>,
        ) -> anyhow::Result<()> {
            self.timeouts.lock().push(timeout);
            {
                let mut running = self.running.lock();
                let count = running.entry(probe.chip.clone()).or_default();
                if *count > 0 {
                    self.overlaps.fetch_add(1, Ordering::SeqCst);
                }
                *count += 1;
                let total = running.values().sum();
                self.max_concurrent.fetch_max(total, Ordering::SeqCst);
            }

            let res = self.script(elf, &cancel);

            *self.running.lock().get_mut(&probe.chip).unwrap() -= 1;
            res
        }
    }

    fn setup() -> (Arc<FakeRunner>, Arc<Mutex<Context>>) {
        static INIT: Once = Once::new();
        INIT.call_once(crate::logutil::init_logger);

        let fake = Arc::new(FakeRunner::default());
        let config: Config = serde_yaml::from_str(CONFIG).unwrap();
        let cx = Arc::new(Mutex::new(Context {
            oidc_client: None,
            queue: Queue::new(Duration::from_secs(config.reserve_after_secs)),
            config,
            runner: fake.clone(),
        }));
        (fake, cx)
    }

    async fn post(cx: &Arc<Mutex<Context>>, path: &str, auth: Option<&str>, body: &str) -> (StatusCode, String) {
        let mut req = warp::test::request().method("POST").path(path).body(body);
        if let Some(auth) = auth {
            req = req.header("Authorization", auth);
        }
        let res = req.reply(&routes(cx.clone())).await;
        (res.status(), String::from_utf8_lossy(res.body()).into_owned())
    }

    /// Request body for a group, from `(target, script)` pairs.
    fn group(members: &[(&str, &str)]) -> String {
        serde_json::to_string(&api::RunRequest {
            members: members
                .iter()
                .map(|(target, script)| api::RunMember {
                    target: target.to_string(),
                    elf: script.as_bytes().to_vec(),
                })
                .collect(),
        })
        .unwrap()
    }

    async fn run_group(cx: &Arc<Mutex<Context>>, members: &[(&str, &str)]) -> (StatusCode, api::RunResponse) {
        let (status, body) = post(cx, "/targets/run", Some("Bearer secret"), &group(members)).await;
        let res = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{}: {}", e, body));
        (status, res)
    }

    /// Runs a group of one, and returns its status and logs.
    async fn run(cx: &Arc<Mutex<Context>>, target: &str, script: &str) -> (StatusCode, String) {
        let (status, mut res) = run_group(cx, &[(target, script)]).await;
        (status, res.members.remove(0).logs)
    }

    async fn wait_until(cond: impl Fn() -> bool) {
        let start = Instant::now();
        while !cond() {
            assert!(start.elapsed() < Duration::from_secs(5), "condition not reached");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn run_ok() {
        let (_fake, cx) = setup();
        let (status, logs) = run(&cx, "a", "ok").await;
        assert_eq!(status, StatusCode::OK);
        assert!(logs.contains("fake run ok"), "logs: {}", logs);
    }

    #[tokio::test]
    async fn run_fail() {
        let (_fake, cx) = setup();
        let (status, logs) = run(&cx, "a", "fail").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(logs.contains("fake failure"), "logs: {}", logs);
    }

    #[tokio::test]
    async fn unknown_target() {
        let (fake, cx) = setup();
        let (status, body) = post(&cx, "/targets/run", Some("Bearer secret"), &group(&[("nope", "ok")])).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "Target not found: nope");
        assert!(fake.timeouts.lock().is_empty());
    }

    #[tokio::test]
    async fn bad_auth() {
        let (fake, cx) = setup();
        let body = group(&[("a", "ok")]);
        let (status, _) = post(&cx, "/targets/run", None, &body).await;
        assert!(!status.is_success(), "missing header: {}", status);
        let (status, _) = post(&cx, "/targets/run", Some("secret"), &body).await;
        assert!(!status.is_success(), "no Bearer prefix: {}", status);
        let (status, _) = post(&cx, "/targets/run", Some("Bearer wrong"), &body).await;
        assert!(!status.is_success(), "wrong token: {}", status);
        assert!(fake.timeouts.lock().is_empty());
    }

    #[tokio::test]
    async fn timeout_default_and_clamp() {
        let (fake, cx) = setup();
        run(&cx, "a", "ok").await;
        let body = group(&[("a", "ok")]);
        post(&cx, "/targets/run?timeout=5", Some("Bearer secret"), &body).await;
        post(&cx, "/targets/run?timeout=1000", Some("Bearer secret"), &body).await;
        assert_eq!(
            *fake.timeouts.lock(),
            [Duration::from_secs(10), Duration::from_secs(5), Duration::from_secs(60)]
        );
    }

    #[tokio::test]
    async fn same_target_is_serialized() {
        let (fake, cx) = setup();
        let (r1, r2) = tokio::join!(run(&cx, "a", "sleep:100"), run(&cx, "a", "sleep:100"));
        assert_eq!((r1.0, r2.0), (StatusCode::OK, StatusCode::OK));
        assert_eq!(fake.overlaps.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn different_targets_run_concurrently() {
        let (fake, cx) = setup();
        let (r1, r2) = tokio::join!(run(&cx, "a", "sleep:200"), run(&cx, "b", "sleep:200"));
        assert_eq!((r1.0, r2.0), (StatusCode::OK, StatusCode::OK));
        assert_eq!(fake.max_concurrent.load(Ordering::SeqCst), 2);
    }

    /// Sends a run request over a real connection, and returns the connection so the test can drop it.
    async fn start_run(cx: &Arc<Mutex<Context>>, members: &[(&str, &str)]) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(warp::serve(routes(cx.clone())).incoming(listener).run());

        let body = group(members);
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /targets/run HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer secret\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream
    }

    /// A client that disconnects mid-run must not free the target while the run is still stopping.
    #[tokio::test]
    async fn disconnect_keeps_target_locked() {
        let (fake, cx) = setup();
        let stream = start_run(&cx, &[("a", "sleep:500")]).await;
        wait_until(|| fake.is_running("chip-a")).await;
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (status, _) = run(&cx, "a", "ok").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            fake.overlaps.load(Ordering::SeqCst),
            0,
            "second run started while the first was still running"
        );
    }

    /// Same for a group: after a disconnect, a member that already finished keeps its target until the
    /// rest of the group has stopped.
    #[tokio::test]
    async fn disconnect_keeps_group_locked() {
        let (fake, cx) = setup();
        let stream = start_run(&cx, &[("a", "ok"), ("b", "sleep:500")]).await;
        wait_until(|| fake.is_running("chip-b")).await;
        drop(stream);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (status, _) = run(&cx, "a", "ok").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!fake.is_running("chip-b"), "a was free while b was still running");
    }

    #[tokio::test]
    async fn group_members_run_concurrently() {
        let (fake, cx) = setup();
        let (status, res) = run_group(&cx, &[("a", "sleep:200"), ("b", "sleep:200")]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(res.ok);
        assert_eq!(fake.max_concurrent.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn group_fails_if_any_member_fails() {
        let (_fake, cx) = setup();
        let (status, res) = run_group(&cx, &[("a", "ok"), ("b", "fail")]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!res.ok);

        let [a, b] = &res.members[..] else { panic!("{:?}", res) };
        assert_eq!((a.target.as_str(), a.ok, a.reason.as_deref()), ("a", true, None));
        assert_eq!(
            (b.target.as_str(), b.ok, b.reason.as_deref()),
            ("b", false, Some("fake failure"))
        );
        // Each member gets only its own logs.
        assert!(
            a.logs.contains("fake run ok") && !a.logs.contains("fake failure"),
            "{}",
            a.logs
        );
        assert!(
            b.logs.contains("fake failure") && !b.logs.contains("fake run ok"),
            "{}",
            b.logs
        );
    }

    #[tokio::test]
    async fn invalid_groups_are_rejected() {
        let (fake, cx) = setup();
        let post = |body: String| {
            let cx = cx.clone();
            async move { post(&cx, "/targets/run", Some("Bearer secret"), &body).await }
        };

        let (status, body) = post(group(&[])).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, "Request has no members")
        );

        let (status, body) = post(group(&[("a", "ok"), ("a", "ok")])).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, "Duplicate target: a")
        );

        let (status, body) = post(r#"{"members":[{"target":"a","elf":"not base64!"}]}"#.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.starts_with("Invalid request:"), "{}", body);

        // One unknown member rejects the whole group, and nothing runs.
        let (status, body) = post(group(&[("a", "ok"), ("nope", "ok")])).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::NOT_FOUND, "Target not found: nope")
        );

        assert!(fake.timeouts.lock().is_empty());
    }

    /// A member that finishes early keeps its target until the whole group is done.
    #[tokio::test]
    async fn group_holds_targets_until_last_member_finishes() {
        let (fake, cx) = setup();
        let grp = tokio::spawn({
            let cx = cx.clone();
            async move { run_group(&cx, &[("a", "ok"), ("b", "sleep:300")]).await }
        });
        wait_until(|| fake.is_running("chip-b")).await;

        let (status, _) = run(&cx, "a", "ok").await;
        assert_eq!(status, StatusCode::OK);
        assert!(!fake.is_running("chip-b"), "a was free while b was still running");
        assert_eq!(grp.await.unwrap().0, StatusCode::OK);
    }

    #[tokio::test]
    async fn failure_cancels_group() {
        let (fake, cx) = setup();
        let start = Instant::now();
        let (status, res) = run_group(&cx, &[("a", "fail"), ("b", "sleep:10000")]).await;
        assert!(start.elapsed() < Duration::from_secs(2), "took {:?}", start.elapsed());
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let [a, b] = &res.members[..] else { panic!("{:?}", res) };
        assert_eq!(a.reason.as_deref(), Some("fake failure"));
        assert_eq!(b.reason.as_deref(), Some("Cancelled"));
        assert_eq!(fake.cancelled.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disconnect_cancels_run() {
        let (fake, cx) = setup();
        let stream = start_run(&cx, &[("a", "sleep:10000")]).await;
        wait_until(|| fake.is_running("chip-a")).await;
        drop(stream);

        wait_until(|| !fake.is_running("chip-a")).await;
        assert_eq!(fake.cancelled.load(Ordering::SeqCst), 1);
        let (status, _) = run(&cx, "a", "ok").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Only failures cancel. A member that passes early doesn't stop the others.
    #[tokio::test]
    async fn pass_does_not_cancel_group() {
        let (fake, cx) = setup();
        let (status, res) = run_group(&cx, &[("a", "ok"), ("b", "sleep:200")]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(res.ok);
        assert_eq!(fake.cancelled.load(Ordering::SeqCst), 0);
    }
}
