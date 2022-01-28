use anyhow::anyhow;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct ProbeSpecifier {
    pub vid_pid: Option<(u16, u16)>,
    pub serial: Option<String>,
}

impl<'de> Deserialize<'de> for ProbeSpecifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for ProbeSpecifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match (self.vid_pid.as_ref(), self.serial.as_ref()) {
            (None, None) => panic!("Invalid probe filter"),
            (None, Some(serial)) => serializer.serialize_str(serial),
            (Some((vid, pid)), None) => serializer.serialize_str(&format!("{:x}:{:x}", vid, pid)),
            (Some((vid, pid)), Some(serial)) => {
                serializer.serialize_str(&format!("{:x}:{:x}:{}", vid, pid, serial))
            }
        }
    }
}

impl FromStr for ProbeSpecifier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(':').collect::<Vec<_>>();
        match &*parts {
            [serial] => Ok(Self {
                vid_pid: None,
                serial: Some(serial.to_string()),
            }),
            [vid, pid] => Ok(Self {
                vid_pid: Some((u16::from_str_radix(vid, 16)?, u16::from_str_radix(pid, 16)?)),
                serial: None,
            }),
            [vid, pid, serial] => Ok(Self {
                vid_pid: Some((u16::from_str_radix(vid, 16)?, u16::from_str_radix(pid, 16)?)),
                serial: Some(serial.to_string()),
            }),
            _ => Err(anyhow!("invalid probe filter")),
        }
    }
}
