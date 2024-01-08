use core::any::Any;
use core::pin::Pin;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};
use std::sync::OnceLock;
use std::task::{Context, Poll};

use chrono::{DateTime, Utc};
use log::{LevelFilter, Log, Record};
use pin_project_lite::pin_project;
use pretty_env_logger::env_logger::filter::{self, Filter};
use pretty_env_logger::env_logger::Logger;
use serde::{Deserialize, Serialize};

static LOGGER: OnceLock<CaptureLogger> = OnceLock::new();

pub(crate) fn init() {
    let mut inner_logger = pretty_env_logger::formatted_builder();
    inner_logger.parse_filters("trace");
    let inner_logger = inner_logger.build();

    let mut ui_filter = filter::Builder::new();
    if let Ok(s) = ::std::env::var("RUST_LOG") {
        ui_filter.parse(&s);
    } else {
        ui_filter.filter_level(LevelFilter::Error);
        ui_filter.filter_module("teleprobe", LevelFilter::Info);
        ui_filter.filter_module("device", LevelFilter::Trace);
    }
    let ui_filter = ui_filter.build();

    let mut capture_filter = filter::Builder::new();
    if let Ok(s) = ::std::env::var("RUST_LOG_CAPTURE") {
        capture_filter.parse(&s);
    } else {
        capture_filter.filter_level(LevelFilter::Warn);
        //capture_filter.filter_module("teleprobe", LevelFilter::Trace);
        //capture_filter.filter_module("probe_rs::flashing", LevelFilter::Debug);
        capture_filter.filter_module("teleprobe", LevelFilter::Info);
        capture_filter.filter_module("device", LevelFilter::Trace);
    }

    let capture_filter = capture_filter.build();

    let logger = CaptureLogger {
        ui_filter,
        capture_filter,
        logger: inner_logger,
    };
    LOGGER.set(logger).map_err(|_| ()).unwrap();

    log::set_max_level(LevelFilter::Trace);
    log::set_logger(LOGGER.get().unwrap()).unwrap();
    log_panics::init();
}

pub fn with_capture<F, R>(f: F) -> (R, Vec<LogEntry>)
where
    F: FnOnce() -> R,
{
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let res = f();
    let entries = CAPTURE.with(|c| c.borrow_mut().take().unwrap());
    (res, entries)
}

thread_local! {
    pub static CAPTURE: RefCell<Option<Vec<LogEntry>>> = RefCell::new(None);
}

struct CaptureLogger {
    ui_filter: Filter,
    capture_filter: Filter,
    logger: Logger,
}

impl Log for CaptureLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.ui_filter.enabled(metadata) || self.capture_filter.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.ui_filter.matches(record) {
            self.logger.log(record);
        }
        if self.capture_filter.matches(record) {
            CAPTURE.with(|c| {
                if let Some(entries) = c.borrow_mut().as_mut() {
                    entries.push(LogEntry::from_record(record))
                }
            });
        }
    }

    fn flush(&self) {
        self.logger.flush()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub message: String,
    pub level: String,
    pub module_path: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

impl LogEntry {
    fn from_record(record: &Record) -> Self {
        LogEntry {
            message: record.args().to_string(),
            level: record.level().to_string(),
            module_path: record.module_path().map(|s| s.to_string()),
            file: record.file().map(|s| s.to_string()),
            line: record.line(),
            timestamp: Utc::now(),
        }
    }
}

mod log_panics {
    //! A crate which logs panics instead of writing to standard error.
    //!
    //! The format used is identical to the standard library's.
    //!
    //! Because logging with a backtrace requires additional dependencies,
    //! the `with-backtrace` feature must be enabled. You can add the
    //! following in your `Cargo.toml`:
    //!
    //! ```toml
    //! log-panics = { version = "2", features = ["with-backtrace"]}
    //! ```
    //!
    //! To use, call [`log_panics::init()`](init) somewhere early in execution,
    //! such as immediately after initializing `log`, or use the [`Config`]
    //! builder for more customization.

    //#![doc(html_root_url = "https://docs.rs/log-panics/2.0.0")]
    #![warn(missing_docs)]
    // Enable feature requirements on docs.rs.
    #![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

    use std::process::abort;
    use std::{fmt, panic, thread};

    use backtrace::Backtrace;

    use super::CATCHING_UNWIND;

    struct Shim(Backtrace);

    impl fmt::Debug for Shim {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            if !self.0.frames().is_empty() {
                write!(fmt, "\n{:?}", self.0)
            } else {
                Ok(())
            }
        }
    }

    /// Configures the panic hook, ending with initialization.
    ///
    /// ## Example
    ///
    /// ```
    /// # #[cfg(feature = "with-backtrace")]
    /// log_panics::Config::new()
    ///     .backtrace_mode(log_panics::BacktraceMode::Unresolved)
    ///     .install_panic_hook()
    /// ```
    #[derive(Debug)]
    pub struct Config {
        // We store a constructor function instead of a BacktraceMode enum
        // so that inlining can eliminate references to `Backtrace::default`
        // if symbolication is not desired.
        make_backtrace: fn() -> Backtrace,
    }

    impl Config {
        /// Initializes the builder with the default set of features.
        pub fn new() -> Self {
            Self {
                make_backtrace: Backtrace::default,
            }
        }

        /// Initializes the panic hook.
        ///
        /// After this method is called, all panics will be logged rather than printed
        /// to standard error.
        pub fn install_panic_hook(self) {
            panic::set_hook(Box::new(move |info| {
                let backtrace = (self.make_backtrace)();

                let thread = thread::current();
                let thread = thread.name().unwrap_or("<unnamed>");

                let msg = match info.payload().downcast_ref::<&'static str>() {
                    Some(s) => *s,
                    None => match info.payload().downcast_ref::<String>() {
                        Some(s) => &**s,
                        None => "Box<Any>",
                    },
                };

                match info.location() {
                    Some(location) => {
                        log::error!(
                            target: "panic", "thread '{}' panicked at '{}': {}:{}{:?}",
                            thread,
                            msg,
                            location.file(),
                            location.line(),
                            Shim(backtrace)
                        );
                    }
                    None => log::error!(
                        target: "panic",
                        "thread '{}' panicked at '{}'{:?}",
                        thread,
                        msg,
                        Shim(backtrace)
                    ),
                }

                let catching = CATCHING_UNWIND.with(|c| c.get());

                if !catching {
                    // on windows, the terminal window will close immediately, preventing
                    // the user from seeing the panic message, unless we wait for a keypress.
                    #[cfg(windows)]
                    let _ = std::process::Command::new("cmd.exe").arg("/c").arg("pause").status();

                    // if one task panics, tokio does not abort the process, so we do it ourselves.
                    // https://github.com/tokio-rs/tokio/issues/2002
                    abort()
                }
            }));
        }
    }

    impl Default for Config {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Initializes the panic hook with the default settings.
    ///
    /// After this method is called, all panics will be logged rather than printed
    /// to standard error.
    ///
    /// See [`Config`] for more information.
    pub fn init() {
        Config::new().install_panic_hook()
    }
}

thread_local! {
     static CATCHING_UNWIND: Cell<bool> = Cell::new(false);
}

pin_project! {
    /// Future for the [`catch_unwind`](super::FutureExt::catch_unwind) method.
    #[derive(Debug)]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct CatchUnwind<Fut> {
        #[pin]
        future: Fut,
    }
}

impl<Fut> CatchUnwind<Fut>
where
    Fut: Future + UnwindSafe,
{
    fn new(future: Fut) -> Self {
        Self { future }
    }
}

impl<Fut> Future for CatchUnwind<Fut>
where
    Fut: Future + UnwindSafe,
{
    type Output = Result<Fut::Output, Box<dyn Any + Send>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let prev = CATCHING_UNWIND.with(|c| c.replace(true));

        let f = self.project().future;
        let res = catch_unwind(AssertUnwindSafe(|| f.poll(cx)))?.map(Ok);

        CATCHING_UNWIND.with(|c| c.set(prev));
        res
    }
}

pub trait FutureExt: Future {
    fn ak_catch_unwind(self) -> CatchUnwind<Self>
    where
        Self: Sized + ::std::panic::UnwindSafe,
    {
        CatchUnwind::new(self)
    }
}

impl<T: ?Sized> FutureExt for T where T: Future {}
