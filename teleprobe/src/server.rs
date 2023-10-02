use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use bytes::Bytes;
use log::{error, info};
use parking_lot::Mutex;
use probe_rs::Probe;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::spawn_blocking;
use warp::hyper::StatusCode;
use warp::reply::{html, with_status};
use warp::{Filter, Rejection, Reply};

use crate::auth::oidc;
use crate::auth::oidc::Client;
use crate::config::{Auth, Config, OidcAuthRule};
use crate::probe::probes_filter;
use crate::{api, probe, run};

fn run_firmware_on_device(elf: Bytes, probe: probe::Opts, timeout: Duration) -> anyhow::Result<()> {
    // Retry 10 times.
    let mut res = Err(anyhow!("bah"));
    for _ in 0..10 {
        res = probe::connect(&probe);
        if res.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let mut sess = res?;

    let opts = run::Options {
        deadline: Some(Instant::now() + timeout),
        ..Default::default()
    };
    run::run(&mut sess, &elf, opts)?;

    Ok(())
}

async fn run_with_log_capture(elf: Bytes, probe: probe::Opts, timeout: Duration) -> (bool, Vec<u8>) {
    let (ok, entries) = spawn_blocking(move || {
        crate::logutil::with_capture(|| match run_firmware_on_device(elf, probe, timeout) {
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
                info!("Auth method {} #{} failed: {:?}", auth.to_string(), i, e)
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

    let target_mutex = cx
        .lock()
        .target_locks
        .entry(target.name.clone())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone();

    let _target_guard = target_mutex.lock().await;

    let probe = probe::Opts {
        chip: target.chip.clone(),
        connect_under_reset: target.connect_under_reset,
        probe: Some(target.probe.clone()),
        speed: target.speed,
        power_reset: target.power_reset,
    };

    let timeout = {
        let config = &mut cx.lock().config;
        Duration::from_secs(args.timeout.unwrap_or(config.default_timeout).min(config.max_timeout))
    };

    let (ok, logs) = run_with_log_capture(elf, probe, timeout).await;
    let status = if ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };

    Ok(with_status(logs, status))
}

fn targets(cx: Arc<Mutex<Context>>) -> api::TargetList {
    let targets = cx.lock().config.targets.clone();
    let mut res = Vec::new();
    let up_probes = Probe::list_all();

    for target in targets {
        let is_up = !probes_filter(&up_probes, &target.probe).is_empty();
        res.push(api::Target {
            name: target.name,
            chip: target.chip,
            probe: target.probe,
            connect_under_reset: target.connect_under_reset,
            speed: target.speed,
            up: is_up,
            power_reset: target.power_reset,
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
    target_locks: HashMap<String, Arc<AsyncMutex<()>>>,
}

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let config = fs::read("config.yaml")?;
    let config: Config = serde_yaml::from_slice(&config)?;

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
        config,
        target_locks: HashMap::new(),
    }));

    let target_run: _ = warp::path!("targets" / String / "run")
        .and(warp::post())
        .and(check_auth_filter(context.clone()))
        .and(warp::query())
        .and(warp::body::bytes())
        .and(with_val(context.clone()))
        .and_then(handle_run);

    let list_targets: _ = warp::path!("targets")
        .and(warp::get())
        .and(check_auth_filter(context.clone()))
        .and(with_val(context.clone()))
        .and_then(handle_list_targets);

    let home: _ = warp::path!()
        .and(warp::get())
        .and(with_val(context.clone()))
        .and_then(handle_home);

    info!("Listening on :{}", port);
    warp::serve(target_run.or(list_targets).or(home))
        .run(([0, 0, 0, 0], port))
        .await;

    Ok(())
}

fn with_val<T: Clone + Send>(val: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}
