//! Reader for RTT up channel 0, which carries the defmt stream.
//!
//! While some chips are in Stop mode (seen on STM32L0 and STM32L5, with DBGMCU's DBG_STOP set),
//! every debugger read of the system bus returns 0 and the probe reports success. Data read in
//! that state can't be told apart from real data, and the read pointer written back in that
//! state is dropped. So this reader:
//!
//! - checks the control block before and after reading the data, and discards the data if the
//!   control block wasn't readable both times, without writing the read pointer;
//! - writes the read pointer only after the data was accepted, and on the next read checks that
//!   the write landed. A write that was dropped is done again, so the data isn't read twice.
//!
//! The firmware only writes RTT while it runs, so nothing is lost by waiting until the chip is
//! out of Stop.

use std::time::Instant;

use probe_rs::MemoryInterface;

const ID: &[u8; 16] = b"SEGGER RTT\0\0\0\0\0\0";

/// Control block ID, max up and down channel counts, and the up channel 0 descriptor.
const HEADER_LEN: usize = 16 + 4 + 4 + 24;
/// Offset of up channel 0's read offset in the control block.
const READ_OFFSET: u64 = 16 + 4 + 4 + 16;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Header {
    buffer: u32,
    size: u32,
    write: u32,
    read: u32,
}

pub struct RttReader {
    control_block: u32,
    /// Read offset written by the last read, and the one it replaced.
    written: Option<(u32, u32)>,
    unreadable_since: Option<Instant>,
}

impl RttReader {
    pub fn new(control_block: u32) -> Self {
        Self {
            control_block,
            written: None,
            unreadable_since: None,
        }
    }

    /// Reads the control block, or `None` if it isn't valid right now.
    fn header(&self, memory: &mut impl MemoryInterface) -> anyhow::Result<Option<Header>> {
        let mut b = [0u8; HEADER_LEN];
        memory.read(self.control_block as u64, &mut b)?;
        if &b[..16] != ID {
            return Ok(None);
        }
        let word = |offset: usize| u32::from_le_bytes(b[offset..offset + 4].try_into().unwrap());
        if word(16) == 0 {
            return Ok(None);
        }
        let header = Header {
            buffer: word(28),
            size: word(32),
            write: word(36),
            read: word(40),
        };
        if header.size == 0 || header.write >= header.size || header.read >= header.size {
            return Ok(None);
        }
        Ok(Some(header))
    }

    /// Appends the available data to `out`. Returns the number of bytes appended.
    pub fn read(&mut self, memory: &mut impl MemoryInterface, out: &mut Vec<u8>) -> anyhow::Result<usize> {
        let Some(header) = self.header(memory)? else {
            self.unreadable();
            return Ok(0);
        };
        self.readable();

        let mut read = header.read;
        match self.written {
            Some((_, new)) if new == header.read => {}
            Some((old, new)) if old == header.read => {
                // Our last write of the read offset was dropped. The data up to `new` was already
                // returned.
                log::debug!("RTT read offset write was lost, writing it again");
                read = new;
            }
            Some((_, new)) => {
                log::warn!(
                    "RTT read offset changed by the target (expected {new:#x}, got {:#x}), following it",
                    header.read
                );
            }
            None => {}
        }

        let start = out.len();
        if header.write >= read {
            self.read_data(memory, &header, read, header.write, out)?;
        } else {
            self.read_data(memory, &header, read, header.size, out)?;
            self.read_data(memory, &header, 0, header.write, out)?;
        }
        let n = out.len() - start;

        if n > 0 {
            // The data is only valid if the memory was readable for the whole read.
            if self.header(memory)?.map(|h| (h.buffer, h.size, h.read))
                != Some((header.buffer, header.size, header.read))
            {
                out.truncate(start);
                self.unreadable();
                return Ok(0);
            }
        }

        let new_read = if n > 0 { header.write } else { read };
        if new_read != header.read {
            memory.write_word_32(self.control_block as u64 + READ_OFFSET, new_read)?;
        }
        self.written = Some((header.read, new_read));
        Ok(n)
    }

    fn read_data(
        &self,
        memory: &mut impl MemoryInterface,
        header: &Header,
        from: u32,
        to: u32,
        out: &mut Vec<u8>,
    ) -> anyhow::Result<()> {
        if to > from {
            let start = out.len();
            out.resize(start + (to - from) as usize, 0);
            memory.read(header.buffer as u64 + from as u64, &mut out[start..])?;
        }
        Ok(())
    }

    fn unreadable(&mut self) {
        if self.unreadable_since.is_none() {
            log::debug!("RTT control block not readable, waiting");
            self.unreadable_since = Some(Instant::now());
        }
    }

    fn readable(&mut self) {
        if let Some(since) = self.unreadable_since.take() {
            log::debug!("RTT control block readable again after {:?}", since.elapsed());
        }
    }
}
