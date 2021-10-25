use std::cell::RefCell;

use log::{LevelFilter, Log};

static GLOBAL_LOGGER: GlobalLogger = GlobalLogger;
static mut DEFAULT_LOGGER: Option<&'static dyn Log> = None;

thread_local! {
    pub static LOCAL_LOGGER: RefCell<Option<Box<dyn Log>>> = RefCell::new(None);
}

/// Logger that forwards to the currently enabled thread-local logger.
struct GlobalLogger;

impl Log for GlobalLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        LOCAL_LOGGER.with(|logger| match &*logger.borrow() {
            Some(logger) => logger.enabled(metadata),
            None => false,
        })
    }

    fn log(&self, record: &log::Record) {
        unsafe { DEFAULT_LOGGER }.unwrap().log(record);
        LOCAL_LOGGER.with(|logger| match &*logger.borrow() {
            Some(logger) => logger.log(record),
            None => {}
        })
    }

    fn flush(&self) {
        unsafe { DEFAULT_LOGGER }.unwrap().flush();
        LOCAL_LOGGER.with(|logger| match &*logger.borrow() {
            Some(logger) => logger.flush(),
            None => {}
        })
    }
}

pub fn init(default_logger: Box<dyn Log>) {
    unsafe { DEFAULT_LOGGER = Some(Box::leak(default_logger)) }
    log::set_max_level(LevelFilter::Trace);
    log::set_logger(&GLOBAL_LOGGER).unwrap();
}

pub fn set_local_logger(logger: Box<dyn Log>) {
    LOCAL_LOGGER.with(|l| *l.borrow_mut() = Some(logger));
}
