use serde::{Deserialize, Serialize};

use crate::probe::ProbeSpecifier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub chip: String,
    pub probe: ProbeSpecifier,
    pub connect_under_reset: bool,
    pub speed: Option<u32>,
    pub up: bool,
    pub power_reset: bool,
    pub cycle_delay_seconds: f64,
    pub max_settle_time_millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetList {
    pub targets: Vec<Target>,
}
