use std::process::Command;
use std::time::Instant;

use anyhow::{bail, Result};
use clap::Parser;
use probe_rs::{DebugProbeSelector, Lister, MemoryInterface, Permissions, Probe, Session};

const SETTLE_REPROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

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
}

pub fn list() -> Result<()> {
    let lister = Lister::new();
    let probes = lister.list_all();

    if probes.is_empty() {
        println!("No probe found!");
        return Ok(());
    }
    for probe in probes {
        println!(
            "{:04x}:{:04x}:{} -- {:?} {}",
            probe.vendor_id,
            probe.product_id,
            probe.serial_number.unwrap_or_else(|| "SN unspecified".to_string()),
            probe.probe_type,
            probe.identifier,
        );
    }

    Ok(())
}

pub fn connect(opts: &Opts) -> Result<Session> {
    if opts.power_reset {
        let Some(selector) = &opts.probe else {
            bail!("power reset requires a serial number");
        };
        if selector.serial_number.is_none() {
            bail!("power reset requires a serial number");
        };

        log::debug!("probe power reset");
        if let Err(err) = power_reset(&selector.serial_number.as_ref().unwrap(), 0.5) {
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
        let target = probe_rs::config::get_target_by_name(&opts.chip)?;
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

    let perms = Permissions::new().allow_erase_all();

    let target = probe_rs::config::get_target_by_name(&opts.chip)?;

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

            Ok(probes[0].open(&lister)?)
        }
        Some(selector) => Ok(lister.open(selector)?),
    }
}

fn power_reset(probe_serial: &str, cycle_delay_seconds: f64) -> Result<()> {
    let output = Command::new("uhubctl")
        .arg("-a")
        .arg("cycle")
        .arg("-d")
        .arg(format!("{:.2}", cycle_delay_seconds))
        .arg("-s")
        .arg(probe_serial)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                bail!(
                    "uhubctl failed for serial \'{}\' with delay {}:  {}",
                    probe_serial,
                    cycle_delay_seconds,
                    String::from_utf8_lossy(&output.stderr)
                )
            }
        }
        Err(e) => bail!("uhubctl failed: {}", e),
    }
}
