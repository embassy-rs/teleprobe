use anyhow::{bail, Result};
use clap::Clap;
use probe_rs::{DebugProbeInfo, Probe, Session};

use crate::config::ProbeFilter;

#[derive(Clone, Clap)]
pub struct Opts {
    /// The probe to use (eg. `VID:PID`, `VID:PID:Serial`, or just `Serial`).
    #[clap(long, env = "PROBE_RUN_PROBE")]
    probe: Option<String>,

    /// The probe clock frequency in kHz
    #[clap(long)]
    speed: Option<u32>,

    /// Chip name
    #[clap(long)]
    chip: String,

    /// Connect to device when NRST is pressed.
    #[clap(long)]
    connect_under_reset: bool,
}

pub fn connect(opts: Opts) -> Result<Session> {
    let probes = Probe::list_all();
    let probes = if let Some(probe_opt) = opts.probe.as_deref() {
        let selector = probe_opt.parse()?;
        probes_filter(&probes, &selector)
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

    let target = probe_rs::config::get_target_by_name(&opts.chip).unwrap();

    let sess = if opts.connect_under_reset {
        probe.attach_under_reset(target)?
    } else {
        probe.attach(target)?
    };
    log::debug!("started session");

    Ok(sess)
}

fn probes_filter(probes: &[DebugProbeInfo], selector: &ProbeFilter) -> Vec<DebugProbeInfo> {
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
