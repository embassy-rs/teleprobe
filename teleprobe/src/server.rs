use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use bytes::Bytes;
use log::{error, info};
use parking_lot::Mutex;
use probe_rs::probe::list::Lister;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use warp::http::StatusCode;
use warp::reply::{html, with_status};
use warp::{Filter, Rejection, Reply};

use crate::auth::oidc;
use crate::auth::oidc::Client;
use crate::config::{Auth, Config, OidcAuthRule};
#[cfg(target_os = "linux")]
use crate::probe::power_enable;
use crate::scheduler::{Grant, Queue};
use crate::{api, probe, run};

/// Runs firmware on a target. Abstracted so the server can be tested without hardware.
trait Runner: Send + Sync {
    fn run(&self, elf: &[u8], probe: &probe::Opts, timeout: Duration) -> anyhow::Result<()>;
}

struct ProbeRunner;

impl Runner for ProbeRunner {
    fn run(&self, elf: &[u8], probe: &probe::Opts, timeout: Duration) -> anyhow::Result<()> {
        let mut sess = probe::connect(probe)?;

        let opts = run::Options {
            deadline: Some(Instant::now() + timeout),
            ..Default::default()
        };
        run::run(&mut sess, elf, opts)?;

        Ok(())
    }
}

async fn run_with_log_capture(
    runner: Arc<dyn Runner>,
    grant: Grant,
    elf: Bytes,
    probe: probe::Opts,
    timeout: Duration,
) -> (bool, Vec<u8>) {
    let (ok, entries) = spawn_blocking(move || {
        // The grant lives in the blocking task, not in the request handler. If the client
        // disconnects, the handler is dropped but the run continues, and must keep the target.
        let _grant = grant;
        crate::logutil::with_capture(|| match runner.run(&elf, &probe, timeout) {
            Ok(()) => true,
            Err(e) => {
                error!("Run failed: {:?}", e);
                false
            }
        })
    })
    .await
    .unwrap();

    let mut res = String::new();
    for entry in entries {
        writeln!(&mut res, "{} - {}", entry.level, entry.message).unwrap();
    }
    (ok, res.into_bytes())
}

macro_rules! reject {
    (StatusCode::$code:ident, $($x:tt)*) => {
        return Ok(with_status(
            format!($($x)*).as_bytes().to_vec(),
            StatusCode::$code,
        ))
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

async fn handle_run(name: String, args: RunArgs, elf: Bytes, cx: Arc<Mutex<Context>>) -> Result<impl Reply, Rejection> {
    let target = {
        let context = cx.lock();
        match context.config.targets.iter().find(|t| t.name == name) {
            Some(x) => x.clone(),
            None => reject!(StatusCode::NOT_FOUND, "Target not found: {}", name),
        }
    };

    let queue = cx.lock().queue.clone();
    let grant = queue.acquire(vec![target.name.clone()]).await;

    let probe = probe::Opts {
        chip: target.chip.clone(),
        connect_under_reset: target.connect_under_reset,
        probe: Some(target.probe.clone()),
        speed: target.speed,
        power_reset: target.power_reset,
        cycle_delay_seconds: target.cycle_delay_seconds,
        max_settle_time_millis: target.max_settle_time_millis,
        protocol: None,
    };

    let (timeout, runner) = {
        let context = cx.lock();
        let config = &context.config;
        let timeout = Duration::from_secs(args.timeout.unwrap_or(config.default_timeout).min(config.max_timeout));
        (timeout, context.runner.clone())
    };

    let (ok, logs) = run_with_log_capture(runner, grant, elf, probe, timeout).await;
    let status = if ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };

    Ok(with_status(logs, status))
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
    let target_run = warp::path!("targets" / String / "run")
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

    /// Stands in for a board. The "ELF" is a script: `ok`, `fail` or `sleep:<ms>`.
    #[derive(Default)]
    struct FakeRunner {
        /// Number of runs currently in progress, per chip.
        running: Mutex<HashMap<String, usize>>,
        /// Number of times a run started on a chip that was already running.
        overlaps: AtomicUsize,
        max_concurrent: AtomicUsize,
        timeouts: Mutex<Vec<Duration>>,
    }

    impl FakeRunner {
        fn is_running(&self, chip: &str) -> bool {
            self.running.lock().get(chip).copied().unwrap_or(0) > 0
        }

        fn script(elf: &[u8]) -> anyhow::Result<()> {
            match std::str::from_utf8(elf)? {
                "ok" => info!("fake run ok"),
                "fail" => bail!("fake failure"),
                s => match s.strip_prefix("sleep:") {
                    Some(ms) => std::thread::sleep(Duration::from_millis(ms.parse()?)),
                    None => bail!("unknown fake script: {}", s),
                },
            }
            Ok(())
        }
    }

    impl Runner for FakeRunner {
        fn run(&self, elf: &[u8], probe: &probe::Opts, timeout: Duration) -> anyhow::Result<()> {
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

            let res = Self::script(elf);

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

    async fn run(cx: &Arc<Mutex<Context>>, target: &str, body: &str) -> (StatusCode, String) {
        post(cx, &format!("/targets/{}/run", target), Some("Bearer secret"), body).await
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
        let (status, body) = run(&cx, "nope", "ok").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "Target not found: nope");
        assert!(fake.timeouts.lock().is_empty());
    }

    #[tokio::test]
    async fn bad_auth() {
        let (fake, cx) = setup();
        let (status, _) = post(&cx, "/targets/a/run", None, "ok").await;
        assert!(!status.is_success(), "missing header: {}", status);
        let (status, _) = post(&cx, "/targets/a/run", Some("secret"), "ok").await;
        assert!(!status.is_success(), "no Bearer prefix: {}", status);
        let (status, _) = post(&cx, "/targets/a/run", Some("Bearer wrong"), "ok").await;
        assert!(!status.is_success(), "wrong token: {}", status);
        assert!(fake.timeouts.lock().is_empty());
    }

    #[tokio::test]
    async fn timeout_default_and_clamp() {
        let (fake, cx) = setup();
        run(&cx, "a", "ok").await;
        post(&cx, "/targets/a/run?timeout=5", Some("Bearer secret"), "ok").await;
        post(&cx, "/targets/a/run?timeout=1000", Some("Bearer secret"), "ok").await;
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

    /// A client that disconnects mid-run must not free the target while the run is still going.
    #[tokio::test]
    async fn disconnect_keeps_target_locked() {
        let (fake, cx) = setup();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(warp::serve(routes(cx.clone())).incoming(listener).run());

        let body = "sleep:500";
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /targets/a/run HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer secret\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
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
}
