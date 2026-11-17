use probe_rs::probe::DebugProbeSelector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub chip: String,
    pub probe: DebugProbeSelector,
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

/// Body of `POST /targets/run`. All members run at the same time, each on its own target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    pub members: Vec<RunMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMember {
    pub target: String,
    #[serde(with = "base64_bytes")]
    pub elf: Vec<u8>,
}

/// Response of `POST /targets/run`. `ok` is true only if every member passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub ok: bool,
    /// In the same order as the request's members.
    pub members: Vec<MemberResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberResult {
    pub target: String,
    pub ok: bool,
    /// Why the member failed, if it did.
    pub reason: Option<String>,
    pub logs: String,
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
