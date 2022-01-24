mod specifier;

use anyhow::{bail, Result};
use clap::Parser;
use probe_rs::{DebugProbeInfo, Probe, Session};

pub use specifier::ProbeSpecifier;

#[derive(Clone, Parser)]
pub struct Opts {
    /// The probe to use (specified by eg. `VID:PID`, `VID:PID:Serial`, or just `Serial`).
    #[clap(long, env = "PROBE_RUN_PROBE")]
    pub probe: Option<ProbeSpecifier>,

    /// The probe clock frequency in kHz
    #[clap(long)]
    pub speed: Option<u32>,

    /// Chip name
    #[clap(long)]
    pub chip: String,

    /// Connect to device when NRST is pressed.
    #[clap(long)]
    pub connect_under_reset: bool,
}

pub fn list() -> Result<()> {
    for probe in Probe::list_all() {
        println!(
            "{:04x}:{:04x}:{} -- {:?} {}",
            probe.vendor_id,
            probe.product_id,
            probe
                .serial_number
                .unwrap_or_else(|| "SN unspecified".to_string()),
            probe.probe_type,
            probe.identifier,
        );
    }

    Ok(())
}

pub fn connect(opts: Opts) -> Result<Session> {
    let probes = Probe::list_all();
    let probes = if let Some(selected_probe) = opts.probe {
        probes_filter(&probes, &selected_probe)
    } else {
        probes
    };

    // ensure exactly one probe is found and open it
    if probes.is_empty() {
        bail!("no probe was found")
    }
    log::debug!("found {} probes", probes.len());
    if probes.len() > 1 {
        //let _ = print_probes(probes);
        bail!("more than one probe found; use --probe to specify which one to use");
    }
    let mut probe = probes[0].open()?;
    log::debug!("opened probe");

    if let Some(speed) = opts.speed {
        probe.set_speed(speed)?;
    }

    let target = probe_rs::config::get_target_by_name(&opts.chip)?;

    let sess = if opts.connect_under_reset {
        probe.attach_under_reset(target)?
    } else {
        probe.attach(target)?
    };
    log::debug!("started session");

    Ok(sess)
}

fn probes_filter(probes: &[DebugProbeInfo], selector: &ProbeSpecifier) -> Vec<DebugProbeInfo> {
    probes
        .iter()
        .filter(|&p| {
            if let Some((vid, pid)) = selector.vid_pid {
                if p.vendor_id != vid || p.product_id != pid {
                    return false;
                }
            }

            if let Some(serial) = &selector.serial {
                if p.serial_number.as_deref() != Some(serial) {
                    return false;
                }
            }

            true
        })
        .cloned()
        .collect()
}
