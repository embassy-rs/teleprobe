use std::io::Write;
use std::sync::{Arc, Mutex};

use env_logger::filter::{Builder, Filter};
use log::Log;

use super::thread_local_logger;

// This struct is used as an adaptor, it implements io::Write and forwards the buffer to a mpsc::Sender
struct CaptureLogger {
    data: Arc<Mutex<Vec<u8>>>,
    filter: Filter,
}

impl Log for CaptureLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.filter.matches(record) {
            let s = &mut *self.data.lock().unwrap();
            writeln!(s, "{} - {}", record.level(), record.args()).unwrap();
        }
    }

    fn flush(&self) {}
}

pub fn with_capture<F, R>(filter: &str, f: F) -> (R, Vec<u8>)
where
    F: FnOnce() -> R,
{
    let data = Arc::new(Mutex::new(Vec::new()));
    thread_local_logger::set_local_logger(Box::new(CaptureLogger {
        data: data.clone(),
        filter: Builder::new().parse(filter).build(),
    }));

    let res = f();

    let data = std::mem::take(&mut *data.lock().unwrap());

    (res, data)
}
