use std::collections::HashMap;
use std::fs;
use std::mem;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::{error, info};
use tokio::task::spawn_blocking;
use warp::hyper::StatusCode;
use warp::reply::with_status;
use warp::{reject, Filter, Rejection, Reply};

use crate::config::Config;
use crate::{log_capture, oidc, probe, run};

pub struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    pub fn new(f: F) -> Self {
        Self {
            f: MaybeUninit::new(f),
        }
    }

    pub fn defuse(self) {
        mem::forget(self)
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}

const DEFAULT_LOG_FILTER: &str = "info,device=trace";

fn do_do_run(elf: Bytes, probe: probe::Opts) -> anyhow::Result<()> {
    let mut sess = probe::connect(probe)?;

    let mut opts = run::Options::default();
    opts.deadline = Some(Instant::now() + Duration::from_secs(5));
    run::run(&mut sess, &elf, opts)?;

    Ok(())
}

async fn do_run(elf: Bytes, probe: probe::Opts) -> (bool, Vec<u8>) {
    let exit = Arc::new(AtomicBool::new(false));
    let exit2 = exit.clone();

    let drop = OnDrop::new(move || {
        println!("dropped");
        exit.store(true, Ordering::SeqCst)
    });

    let res = spawn_blocking(move || {
        log_capture::with_capture(DEFAULT_LOG_FILTER, || match do_do_run(elf, probe) {
            Ok(()) => true,
            Err(e) => {
                error!("Run failed: {}", e);
                false
            }
        })
    })
    .await;

    res.unwrap()
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

async fn handle_run(
    name: String,
    auth_header: String,
    elf: Bytes,
    cx: &Context,
) -> Result<impl Reply, Rejection> {
    println!("header: '{}'", auth_header);
    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => reject!(StatusCode::UNAUTHORIZED, "Bad Authorization header format"),
    };

    let claims: HashMap<String, serde_json::Value> = match cx.oidc_client.validate_token(token) {
        Ok(x) => x,
        Err(e) => reject!("Bad token: {}", e),
    };

    let claims: HashMap<String, String> = claims
        .into_iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::String(s) => Some((k, s)),
            _ => None,
        })
        .collect();
    println!("claims: {:#?}", claims);

    if !cx.config.auth.rules.iter().any(|rule| {
        return rule.claims.iter().all(|(k, v)| claims.get(k) == Some(v));
    }) {
        reject!(StatusCode::UNAUTHORIZED, "Permission denied")
    }

    let target = match cx.config.targets.iter().find(|t| t.name == name) {
        Some(x) => x,
        None => reject!(StatusCode::NOT_FOUND, "Target not found: {}", name),
    };

    let probe = probe::Opts {
        chip: target.chip.clone(),
        connect_under_reset: false,
        probe: Some(target.probe.clone()),
        speed: None,
    };

    let (ok, logs) = do_run(elf, probe).await;
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };

    Ok(with_status(logs, status))
}

struct Context {
    oidc_client: oidc::Client,
    config: Config,
}

pub async fn serve() -> anyhow::Result<()> {
    let config = fs::read("config.yaml")?;
    let config: Config = serde_yaml::from_slice(&config)?;

    let oidc_client = oidc::Client::new_autodiscover(&config.auth.issuer).await?;

    let context = &*Box::leak(Box::new(Context {
        oidc_client,
        config,
    }));

    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let target_run: _ = warp::path!("targets" / String / "run")
        .and(warp::post())
        .and(warp::header("Authorization"))
        .and(warp::body::bytes())
        .and(with_val(context))
        .and_then(handle_run);

    info!("Listening");
    warp::serve(target_run).run(([0, 0, 0, 0], 8080)).await;

    Ok(())
}

fn with_val<T: Clone + Send>(
    val: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || val.clone())
}
