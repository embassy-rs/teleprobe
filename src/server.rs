use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use bytes::Bytes;
use log::{error, info};

use parking_lot::Mutex;
use tokio::task::spawn_blocking;
use warp::hyper::StatusCode;
use warp::reply::with_status;
use warp::{Filter, Rejection, Reply};

use crate::auth::oidc::Client;
use crate::config::{Auth, Config, OidcAuthRule, TargetList};
use crate::{auth::oidc, probe, run};

const DEFAULT_LOG_FILTER: &str = "info,device=trace";

fn run_firmware_on_device(elf: Bytes, probe: probe::Opts) -> anyhow::Result<()> {
    let mut sess = probe::connect(probe)?;

    let opts = run::Options {
        deadline: Some(Instant::now() + Duration::from_secs(10)),
        ..Default::default()
    };
    run::run(&mut sess, &elf, opts)?;

    Ok(())
}

async fn run_with_log_capture(elf: Bytes, probe: probe::Opts) -> (bool, Vec<u8>) {
    spawn_blocking(move || {
        crate::logging::capture::with_capture(DEFAULT_LOG_FILTER, || {
            match run_firmware_on_device(elf, probe) {
                Ok(()) => true,
                Err(e) => {
                    error!("Run failed: {}", e);
                    false
                }
            }
        })
    })
    .await
    .unwrap()
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

fn check_auth_token(
    oidc_client: Option<&Client>,
    token: &str,
    auth: &Auth,
) -> Result<(), anyhow::Error> {
    match auth {
        Auth::Token(auth) => {
            if token != auth.token {
                bail!("Incorrect token")
            }
            Ok(())
        }
        Auth::Oidc(auth) => {
            if let Some(client) = &oidc_client {
                let claims: HashMap<String, serde_json::Value> = match client.validate_token(token)
                {
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

fn check_auth_filter(
    cx: Arc<Mutex<Context>>,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    let with_context = warp::any().map(move || cx.clone());
    warp::header("Authorization")
        .and(with_context)
        .and_then(check_auth)
        .untuple_one()
}

async fn handle_run(
    name: String,
    elf: Bytes,
    cx: Arc<Mutex<Context>>,
) -> Result<impl Reply, Rejection> {
    let target = {
        let context = cx.lock();
        match context.config.targets.iter().find(|t| t.name == name) {
            Some(x) => x.clone(),
            None => reject!(StatusCode::NOT_FOUND, "Target not found: {}", name),
        }
    };

    let probe = probe::Opts {
        chip: target.chip.clone(),
        connect_under_reset: false,
        probe: Some(target.probe.clone()),
        speed: None,
    };

    let (ok, logs) = run_with_log_capture(elf, probe).await;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };

    Ok(with_status(logs, status))
}

async fn handle_list_targets(cx: Arc<Mutex<Context>>) -> Result<impl Reply, Rejection> {
    let targets = TargetList {
        targets: cx.lock().config.targets.clone(),
    };

    Ok(with_status(
        // NOTE (unwrap): error in this call is caused by programmer error and should never be caused by the user data
        serde_json::to_vec_pretty(&targets).unwrap(),
        StatusCode::OK,
    ))
}

#[derive(Clone)]
struct Context {
    oidc_client: Option<oidc::Client>,
    config: Config,
}

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let config = fs::read("config.yaml")?;
    let config: Config = serde_yaml::from_slice(&config)?;

    // TODO support none or multiple oidc issuers.
    let oidc_client = match config.auths.iter().find_map(|a| match a {
        Auth::Oidc(o) => Some(o),
        _ => None,
    }) {
        Some(auth) => oidc::Client::new_autodiscover(&auth.issuer).await.ok(),
        None => None,
    };

    let context: Arc<Mutex<Context>> = Arc::new(Mutex::new(Context {
        oidc_client,
        config,
    }));

    let target_run: _ = warp::path!("targets" / String / "run")
        .and(warp::post())
        .and(check_auth_filter(context.clone()))
        .and(warp::body::bytes())
        .and(with_val(context.clone()))
        .and_then(handle_run);

    let list_targets: _ = warp::path!("targets")
        .and(warp::get())
        .and(check_auth_filter(context.clone()))
        .and(with_val(context.clone()))
        .and_then(handle_list_targets);

    info!("Listening on :{}", port);
    warp::serve(target_run.or(list_targets))
        .run(([0, 0, 0, 0], port))
        .await;

    Ok(())
}

fn with_val<T: Clone + Send>(
    val: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}
