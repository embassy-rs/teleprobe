#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

/// Set the teleprobe target.
///
/// ```rust
/// teleprobe_meta::target!(b"rpi-pico");
/// ```
///
/// Note that you MUST use binary strings `b""`. Regular strings `""` will not work.
#[macro_export]
macro_rules! target {
    ($val:literal) => {
        #[link_section = ".teleprobe.target"]
        #[used]
        #[no_mangle] // prevent invoking the macro multiple times
        static _TELEPROBE_TARGET: [u8; $val.len()] = *$val;
    };
}

/// Set the teleprobe timeout, in seconds.
///
/// ```rust
/// teleprobe_meta::timeout!(60);
/// ```
#[macro_export]
macro_rules! timeout {
    ($val:literal) => {
        #[link_section = ".teleprobe.timeout"]
        #[used]
        #[no_mangle] // prevent invoking the macro multiple times
        static _TELEPROBE_TIMEOUT: u32 = $val;
    };
}
