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
        #[unsafe(link_section = ".teleprobe.target")]
        #[used]
        #[unsafe(no_mangle)] // prevent invoking the macro multiple times
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
        #[unsafe(link_section = ".teleprobe.timeout")]
        #[used]
        #[unsafe(no_mangle)] // prevent invoking the macro multiple times
        static _TELEPROBE_TIMEOUT: u32 = $val;
    };
}

/// Put the binary in a group. The binaries of a group run at the same time, each on its own target, and
/// the group passes only if all of them pass.
///
/// ```rust
/// teleprobe_meta::group!(b"usb-host-device");
/// ```
#[macro_export]
macro_rules! group {
    ($val:literal) => {
        #[unsafe(link_section = ".teleprobe.group")]
        #[used]
        #[unsafe(no_mangle)] // prevent invoking the macro multiple times
        static _TELEPROBE_GROUP: [u8; $val.len()] = *$val;
    };
}
