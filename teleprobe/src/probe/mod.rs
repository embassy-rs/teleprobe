use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use probe_rs::config::Registry;
use probe_rs::probe::list::Lister;
use probe_rs::probe::{DebugProbeSelector, Probe, WireProtocol};
use probe_rs::{MemoryInterface, Permissions, Session};
use tokio::runtime::Handle;

const SETTLE_REPROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone, Parser)]
pub struct Opts {
    /// The probe to use (specified by eg. `VID:PID`, `VID:PID:Serial`, or just `Serial`).
    #[clap(long, env = "PROBE_RUN_PROBE")]
    pub probe: Option<DebugProbeSelector>,

    /// The probe clock frequency in kHz
    #[clap(long)]
    pub speed: Option<u32>,

    /// Chip name
    #[clap(long)]
    pub chip: String,

    /// Connect to device when NRST is pressed.
    #[clap(long)]
    pub connect_under_reset: bool,

    // If the target should be tried to be power cycled via USB
    #[clap(long)]
    pub power_reset: bool,

    #[clap(long, default_value = "1")]
    pub cycle_delay_seconds: f64,

    #[clap(long, default_value = "2000")]
    pub max_settle_time_millis: u64,

    /// Protocol to use for communication to probe.
    #[clap(long)]
    pub protocol: Option<WireProtocol>,
}

pub fn list() -> Result<()> {
    let lister = Lister::new();
    let probes = lister.list_all();

    if probes.is_empty() {
        println!("No probe found!");
        return Ok(());
    }
    for probe in probes {
        let probe_type = probe.probe_type();
        println!(
            "{:04x}:{:04x}:{} -- {} {}",
            probe.vendor_id,
            probe.product_id,
            probe.serial_number.unwrap_or_else(|| "SN unspecified".to_string()),
            probe_type,
            probe.identifier,
        );
    }

    Ok(())
}

pub fn connect(opts: &Opts) -> Result<Session> {
    let registry = Registry::from_builtin_families();

    if opts.power_reset {
        let Some(selector) = &opts.probe else {
            bail!("power reset requires a serial number");
        };
        if selector.serial_number.is_none() {
            bail!("power reset requires a serial number");
        };

        log::debug!("probe power reset");
        if let Err(err) = power_reset(&selector.serial_number.as_ref().unwrap(), 1.0) {
            log::warn!("power reset failed for: {}", err);
        }
    }

    let end: Instant = Instant::now() + std::time::Duration::from_millis(opts.max_settle_time_millis);
    let mut probe = loop {
        if Instant::now() > end {
            bail!("Probe did not appear after the max settle time.")
        }
        std::thread::sleep(SETTLE_REPROBE_INTERVAL);
        match open_probe(opts) {
            Ok(probe) => break probe,
            Err(e) => log::debug!("failed to open probe, will retry: {:?}", e),
        }
    };

    // GIANT HACK to reset both cores in rp2040.
    // Ideally this would be a custom sequence in probe-rs:
    // https://github.com/probe-rs/probe-rs/pull/1603
    if opts.chip.to_ascii_uppercase().starts_with("RP2040") {
        log::debug!("opened probe for rp2040 reset");

        if let Some(speed) = opts.speed {
            probe.set_speed(speed)?;
        }

        let perms = Permissions::new().allow_erase_all();
        let target = registry.get_target_by_name(&opts.chip)?;
        let mut sess = probe.attach(target, perms)?;
        let mut core = sess.core(0)?;

        const PSM_FRCE_ON: u64 = 0x40010000;
        const PSM_FRCE_OFF: u64 = 0x40010004;
        const PSM_WDSEL: u64 = 0x40010008;

        const PSM_SEL_SIO: u32 = 1 << 14;
        const PSM_SEL_PROC0: u32 = 1 << 15;
        const PSM_SEL_PROC1: u32 = 1 << 16;

        const WATCHDOG_CTRL: u64 = 0x40058000;
        const WATCHDOG_CTRL_TRIGGER: u32 = 1 << 31;
        const WATCHDOG_CTRL_ENABLE: u32 = 1 << 30;

        log::debug!("rp2040: resetting SIO and processors");
        core.write_word_32(PSM_WDSEL, PSM_SEL_SIO | PSM_SEL_PROC0 | PSM_SEL_PROC1)?;
        core.write_word_32(WATCHDOG_CTRL, WATCHDOG_CTRL_ENABLE)?;
        core.write_word_32(WATCHDOG_CTRL, WATCHDOG_CTRL_ENABLE | WATCHDOG_CTRL_TRIGGER)?;
        log::debug!("rp2040: reset done, reattaching");

        // reopen probe.
        drop(core);
        drop(sess);
        probe = open_probe(opts)?;
    }

    log::debug!("opened probe");

    if let Some(speed) = opts.speed {
        probe.set_speed(speed)?;
    }

    if let Some(protocol) = opts.protocol {
        probe.select_protocol(protocol)?;
    }

    let perms = Permissions::new().allow_erase_all();

    let target = registry.get_target_by_name(&opts.chip)?;

    let sess = if opts.connect_under_reset {
        probe.attach_under_reset(target, perms)?
    } else {
        probe.attach(target, perms)?
    };
    log::debug!("started session");

    Ok(sess)
}

fn open_probe(opts: &Opts) -> Result<Probe> {
    let lister = Lister::new();

    match &opts.probe {
        None => {
            let probes = lister.list_all();
            if probes.is_empty() {
                bail!("no probe was found")
            }
            if probes.len() > 1 {
                bail!("more than one probe found; use --probe to specify which one to use");
            }

            Ok(probes[0].open()?)
        }
        Some(selector) => Ok(lister.open(selector)?),
    }
}

#[cfg(not(target_os = "linux"))]
fn power_reset(probe_serial: &str, cycle_delay_seconds: f64) -> Result<()> {
    anyhow::bail!("USB power reset is only supported on linux")
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn power_enable() -> Result<()> {
    anyhow::bail!("USB power reset is only supported on linux")
}

#[cfg(target_os = "linux")]
fn power_reset(probe_serial: &str, cycle_delay_seconds: f64) -> Result<()> {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::thread::sleep;
    use std::time::Duration;

    Handle::current().block_on(async {
        let dev = nusb::list_devices()
            .await?
            .find(|d| {
                let serial = d.serial_number().unwrap_or_default();

                serial == probe_serial || to_hex(serial) == probe_serial
            })
            .ok_or_else(|| anyhow!("device with serial {} not found", probe_serial))?;

        let port_path = dev.sysfs_path().join("port");
        let port_path = CString::new(port_path.as_os_str().as_bytes()).unwrap();

        // The USB device goes away when we disable power to it.
        // If we open the port dir we can keep a "handle" to it even if the device goes away, so
        // we can write `disable=0` with openat() to reenable it.
        let port_fd = unsafe { libc::open(port_path.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if port_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        // close port_fd on function exit
        struct CloseFd(i32);
        impl Drop for CloseFd {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _port_fd_close = CloseFd(port_fd);

        let disable_path = CString::new("disable").unwrap();

        // disable port power
        let disable_fd = unsafe { libc::openat(port_fd, disable_path.as_ptr(), libc::O_WRONLY | libc::O_TRUNC) };
        if disable_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe { File::from_raw_fd(disable_fd) }.write_all(b"1")?;

        // sleep
        sleep(Duration::from_secs_f64(cycle_delay_seconds));

        // enable port power
        let disable_fd = unsafe { libc::openat(port_fd, disable_path.as_ptr(), libc::O_WRONLY | libc::O_TRUNC) };
        if disable_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe { File::from_raw_fd(disable_fd) }.write_all(b"0")?;

        Ok(())
    })
}

fn to_hex(s: &str) -> String {
    use std::fmt::Write;
    s.as_bytes().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}"); // Writing a String never fails
        s
    })
}

#[cfg(target_os = "linux")]
pub(crate) async fn power_enable() -> Result<()> {
    use log::{info, warn};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::time::Duration;

    const USB_CLASS_HUB: u8 = 0x09;
    const USB_SS_BCD: u16 = 0x0300;
    const LIBUSB_DT_SUPERSPEED_HUB: u8 = 0x2a;
    const LIBUSB_DT_HUB: u8 = 0x29;
    const HUB_CHAR_LPSM: u8 = 0x0003;
    const HUB_CHAR_COMMON_LPSM: u8 = 0x0000;
    const HUB_CHAR_INDV_PORT_LPSM: u8 = 0x0001;
    const USB_CTRL_GET_TIMEOUT: u64 = 5000;

    for dev in nusb::list_devices().await? {
        // If the device is not a usb hub, continue
        if dev.class() != USB_CLASS_HUB {
            continue;
        }

        let bcd_usb = dev.usb_version();
        let location = dev.bus_id();
        let dev = match dev.open().await {
            Ok(dev) => dev,
            Err(_) => {
                warn!("failed to open device");
                continue;
            }
        };
        let config = match dev.active_configuration() {
            Ok(config) => config,
            Err(_) => {
                warn!("failed to open device configuration");
                continue;
            }
        };

        let desc_type = if bcd_usb >= USB_SS_BCD {
            LIBUSB_DT_SUPERSPEED_HUB
        } else {
            LIBUSB_DT_HUB
        };

        let desc = match dev
            .get_descriptor(desc_type, 0, 0, Duration::from_millis(USB_CTRL_GET_TIMEOUT))
            .await
        {
            Ok(desc) => desc,
            Err(_) => {
                continue;
            }
        };

        let ports = desc[2];

        /* Logical Power Switching Mode */
        let mut lpsm = desc[3] & HUB_CHAR_LPSM;
        if lpsm == HUB_CHAR_COMMON_LPSM && ports == 1 {
            /* For 1 port hubs, ganged power switching is the same as per-port: */
            lpsm = HUB_CHAR_INDV_PORT_LPSM;
        }

        if lpsm == 0 {
            continue;
        }

        info!("Enabling hub: {}:{}", location, config.configuration_value());

        for port in 1..ports {
            let disable_path = format!(
                "/sys/bus/usb/devices/{}:{}/{}-port{}/disable",
                location,
                config.configuration_value(),
                location,
                port
            );

            let disable_path = CString::new(disable_path.as_str().as_bytes()).unwrap();

            let disable_fd = unsafe { libc::open(disable_path.as_ptr(), libc::O_WRONLY) };
            if disable_fd < 0 {
                continue;
            }

            let result = unsafe { File::from_raw_fd(disable_fd) }.write_all(b"0");

            unsafe { libc::close(disable_fd) };

            match result {
                Err(_) => {
                    warn!("failed to enable port {} on hub", port);
                }
                _ => {}
            }
        }
    }

    Ok(())
}
