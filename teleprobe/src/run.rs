use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::Write;
use std::io::Cursor;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use defmt_decoder::{DecodeError, Location, StreamDecoder, Table};
use log::{info, warn};
use object::read::{File as ElfFile, Object as _, ObjectSection as _};
use object::ObjectSymbol;
use probe_rs::config::MemoryRegion;
use probe_rs::flashing::{DownloadOptions, Format};
use probe_rs::rtt::{Rtt, ScanRegion, UpChannel};
use probe_rs::{Core, MemoryInterface, RegisterId, Session};
use probe_rs_debug::{DebugInfo, DebugRegisters};

pub const LR: RegisterId = RegisterId(14);
pub const PC: RegisterId = RegisterId(15);
pub const SP: RegisterId = RegisterId(13);
pub const XPSR: RegisterId = RegisterId(16);

const THUMB_BIT: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(1);

const POLL_SLEEP_MILLIS: u64 = 100;

pub struct Options {
    pub do_flash: bool,
    pub deadline: Option<Instant>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            do_flash: true,
            deadline: None,
        }
    }
}

pub fn run(sess: &mut Session, elf_bytes: &[u8], opts: Options) -> anyhow::Result<()> {
    let mut r = Runner::new(sess, elf_bytes, opts)?;
    r.run(sess)?;
    Ok(())
}

struct Runner {
    opts: Options,

    rtt_addr: u32,
    main_addr: u32,
    vector_table: VectorTable,

    defmt: Rtt,
    defmt_table: Box<Table>,
    defmt_locs: BTreeMap<u64, Location>,
    defmt_stream: Box<dyn StreamDecoder>,

    di: DebugInfo,
}

unsafe fn fuck_it<'a, 'b, T>(wtf: &'a T) -> &'b T {
    std::mem::transmute(wtf)
}

impl Runner {
    fn new(sess: &mut Session, elf_bytes: &[u8], opts: Options) -> anyhow::Result<Self> {
        let elf = ElfFile::parse(elf_bytes)?;

        let di = DebugInfo::from_raw(elf_bytes)?;

        let table = Box::new(defmt_decoder::Table::parse(elf_bytes)?.expect("no defmt table"));
        let locs = table.get_locations(elf_bytes)?;
        if !table.is_empty() && locs.is_empty() {
            log::warn!("insufficient DWARF info; compile your program with `debug = 2` to enable location info");
        }
        //if !table.indices().all(|idx| locs.contains_key(&(idx as u64))) {
        //    bail!("(BUG) location info is incomplete; it will be omitted from the output");
        //}

        // sections used in cortex-m-rt
        // NOTE we won't load `.uninit` so it is not included here
        // NOTE we don't load `.bss` because the app (cortex-m-rt) will zero it
        let candidates = [".vector_table", ".text", ".rodata", ".data"];

        let mut vector_table = None;
        for sect in elf.sections() {
            if let Ok(name) = sect.name() {
                let size = sect.size();
                // skip empty sections
                if candidates.contains(&name) && size != 0 {
                    let start = sect.address();
                    if size % 4 != 0 || start % 4 != 0 {
                        // we could support unaligned sections but let's not do that now
                        bail!("section `{}` is not 4-byte aligned", name);
                    }

                    let start = start.try_into()?;
                    let data = sect
                        .data()?
                        .chunks_exact(4)
                        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                        .collect::<Vec<_>>();

                    if name == ".vector_table" {
                        vector_table = Some(VectorTable {
                            location: start,
                            // Initial stack pointer
                            initial_sp: data[0],
                            reset: data[1],
                            hard_fault: data[3],
                        });
                    }
                }
            }
        }

        let vector_table = vector_table.ok_or_else(|| anyhow!("`.vector_table` section is missing"))?;
        log::debug!("vector table: {:x?}", vector_table);

        // reset ALL cores other than the main one.
        // This is needed for rp2040 core1.
        for (i, _) in sess.list_cores() {
            if i != 0 {
                sess.core(i)?.reset()?;
            }
        }

        let mut run_from_ram = None;
        for r in &sess.target().memory_map {
            match r {
                MemoryRegion::Ram(r) => {
                    if r.range.contains(&(vector_table.location as u64)) {
                        run_from_ram = Some(true);
                    }
                }
                MemoryRegion::Generic(r) => {
                    if r.range.contains(&(vector_table.location as u64)) {
                        run_from_ram = Some(true);
                    }
                }
                MemoryRegion::Nvm(r) => {
                    if r.range.contains(&(vector_table.location as u64)) {
                        run_from_ram = Some(false);
                    }
                }
            }
        }

        let run_from_ram = run_from_ram.unwrap();
        info!("run_from_ram: {:?}", run_from_ram);

        if !opts.do_flash {
            log::info!("skipped flashing");
        } else {
            sess.core(0)?.reset_and_halt(TIMEOUT)?;

            log::info!("flashing program...");
            let mut dopts = DownloadOptions::new();
            dopts.keep_unwritten_bytes = true;
            dopts.verify = true;

            let mut loader = sess.target().flash_loader();
            loader.load_image(sess, &mut Cursor::new(&elf_bytes), Format::Elf, None)?;
            loader.commit(sess, dopts)?;

            //flashing::download_file_with_options(sess, &opts.elf, Format::Elf, dopts)?;
            log::info!("flashing done!");
        }

        let (rtt_addr, main_addr) = get_rtt_main_from(&elf)?;
        let rtt_addr = rtt_addr.ok_or_else(|| anyhow!("RTT is missing"))?;

        {
            let mut core = sess.core(0)?;

            if run_from_ram {
                // On STM32H7 due to RAM ECC (I think?) it's possible that the
                // last written word doesn't "stick" on reset because it's "half written"
                // https://www.st.com/resource/en/application_note/dm00623136-error-correction-code-ecc-management-for-internal-memories-protection-on-stm32h7-series-stmicroelectronics.pdf
                //
                // Do one dummy write to ensure the last word sticks.
                let data = core.read_word_32(vector_table.location as _)?;
                core.write_word_32(vector_table.location as _, data)?;
            }

            core.reset_and_halt(TIMEOUT)?;

            log::debug!("starting device");
            if core.available_breakpoint_units()? == 0 {
                bail!("RTT not supported on device without HW breakpoints");
            }

            if run_from_ram {
                core.write_core_reg(PC, vector_table.reset)?;
                core.write_core_reg(SP, vector_table.initial_sp)?;

                // Write VTOR
                // NOTE this DOES NOT play nice with the softdevice.
                core.write_word_32(0xE000ED08, vector_table.location)?;
                let got_vtor = core.read_word_32(0xE000ED08)?;
                if got_vtor != vector_table.location {
                    panic!(
                        "failed to set VTOR! got {:08x} want {:08x}",
                        got_vtor, vector_table.location
                    )
                }

                // Hacks to get the softdevice to think we're doing a cold boot here.
                //core.write_32(0x2000_005c, &[0]).unwrap();
                //core.write_32(0x2000_0000, &[0x1000, vector_table.location]).unwrap();
            }

            if !run_from_ram {
                // Corrupt the rtt control block so that it's setup fresh again
                // Only do this when running from flash, because when running from RAM the
                // "fake-flashing to RAM" is what initializes it.
                core.write_word_32(rtt_addr as _, 0xdeadc0de)?;

                // RTT control block is initialized pre-main. Run until main before
                // changing to BlockIfFull.
                core.set_hw_breakpoint(main_addr as _)?;
                core.run()?;
                core.wait_for_core_halted(Duration::from_secs(5))?;
                core.clear_hw_breakpoint(main_addr as _)?;
            }

            const OFFSET: u32 = 44;
            const FLAG: u32 = 2; // BLOCK_IF_FULL
            core.write_word_32((rtt_addr + OFFSET) as _, FLAG)?;

            if run_from_ram {
                core.write_8((vector_table.hard_fault & !THUMB_BIT) as _, &[0x00, 0xbe])?;
            } else {
                core.set_hw_breakpoint((vector_table.hard_fault & !THUMB_BIT) as _)?;
            }

            core.run()?;
        }

        let defmt = setup_logging_channel(rtt_addr, sess)?;

        let defmt_stream = unsafe { fuck_it(&table) }.new_stream_decoder();

        Ok(Self {
            opts,
            rtt_addr,
            main_addr,
            vector_table,
            defmt_table: table,
            defmt_locs: locs,
            defmt,
            defmt_stream,
            di,
        })
    }

    fn poll(&mut self, sess: &mut Session) -> anyhow::Result<()> {
        let current_dir = std::env::current_dir()?;

        let mut read_buf = [0; 1024];
        match self
            .defmt
            .up_channel(0)
            .unwrap()
            .read(&mut sess.core(0).unwrap(), &mut read_buf)?
        {
            0 => {
                // Sleep to reduce CPU usage when defmt didn't return any data.
                std::thread::sleep(Duration::from_millis(POLL_SLEEP_MILLIS));
                return Ok(());
            }
            n => self.defmt_stream.received(&read_buf[..n]),
        }

        loop {
            match self.defmt_stream.decode() {
                Ok(frame) => {
                    let loc = self.defmt_locs.get(&frame.index());

                    let (mut file, mut line, mut mod_path) = (None, None, None);
                    if let Some(loc) = loc {
                        let relpath = if let Ok(relpath) = loc.file.strip_prefix(&current_dir) {
                            relpath
                        } else {
                            // not relative; use full path
                            &loc.file
                        };
                        file = Some(relpath.display().to_string());
                        line = Some(loc.line as u32);
                        mod_path = Some(loc.module.clone());
                    };

                    let mut timestamp = String::new();
                    if let Some(ts) = frame.display_timestamp() {
                        timestamp = format!("{} ", ts);
                    }

                    log::logger().log(
                        &log::Record::builder()
                            .level(match frame.level() {
                                Some(level) => match level.as_str() {
                                    "trace" => log::Level::Trace,
                                    "debug" => log::Level::Debug,
                                    "info" => log::Level::Info,
                                    "warn" => log::Level::Warn,
                                    "error" => log::Level::Error,
                                    _ => log::Level::Error,
                                },
                                None => log::Level::Info,
                            })
                            .file(file.as_deref())
                            .line(line)
                            .target("device")
                            //.args(format_args!("{} {:?} {:?}", frame.display_message(), file, line))
                            .args(format_args!("{}{}", timestamp, frame.display_message()))
                            .build(),
                    );
                }
                Err(DecodeError::UnexpectedEof) => break,
                Err(DecodeError::Malformed) => match self.defmt_table.encoding().can_recover() {
                    // if recovery is impossible, abort
                    false => bail!("failed to decode defmt data"),
                    // if recovery is possible, skip the current frame and continue with new data
                    true => log::warn!("failed to decode defmt data"),
                },
            }
        }

        Ok(())
    }

    fn run(&mut self, sess: &mut Session) -> anyhow::Result<()> {
        let mut was_halted = false;

        loop {
            if let Some(deadline) = self.opts.deadline {
                if Instant::now() > deadline {
                    warn!("Deadline exceeded!");
                    let mut core = sess.core(0)?;
                    self.dump_state(&mut core, true)?;
                    bail!("Deadline exceeded")
                }
            }

            self.poll(sess)?;

            let mut core = sess.core(0)?;
            let is_halted = core.core_halted()?;

            if is_halted && was_halted {
                break;
            }
            was_halted = is_halted;
        }

        let mut core = sess.core(0)?;

        let is_hardfault = self.dump_state(&mut core, false)?;
        if is_hardfault {
            bail!("Firmware crashed");
        }

        Ok(())
    }

    fn traceback(&mut self, core: &mut Core) -> anyhow::Result<()> {
        let mut r = [0; 17];
        for (i, val) in r.iter_mut().enumerate() {
            *val = core.read_core_reg::<u32>(i as u16)?;
        }
        info!(
            "  R0: {:08x}   R1: {:08x}   R2: {:08x}   R3: {:08x}",
            r[0], r[1], r[2], r[3],
        );
        info!(
            "  R4: {:08x}   R5: {:08x}   R6: {:08x}   R7: {:08x}",
            r[4], r[5], r[6], r[7],
        );
        info!(
            "  R8: {:08x}   R9: {:08x}  R10: {:08x}  R11: {:08x}",
            r[8], r[9], r[10], r[11],
        );
        info!(
            " R12: {:08x}   SP: {:08x}   LR: {:08x}   PC: {:08x}",
            r[12], r[13], r[14], r[15],
        );
        info!("XPSR: {:08x}", r[16]);

        info!("");
        info!("Stack:");
        let mut stack = [0u32; 32];
        core.read_32(r[13] as _, &mut stack)?;
        for i in 0..(stack.len() / 4) {
            info!(
                "{:08x}: {:08x} {:08x} {:08x} {:08x}",
                r[13] + i as u32 * 16,
                stack[i * 4 + 0],
                stack[i * 4 + 1],
                stack[i * 4 + 2],
                stack[i * 4 + 3],
            );
        }

        info!("");
        info!("Backtrace:");
        let di = &self.di;
        let initial_registers = DebugRegisters::from_core(core);
        let exception_handler = probe_rs_debug::exception_handler_for_core(core.core_type());
        let instruction_set = core.instruction_set().ok();
        let stack_frames = di.unwind(core, initial_registers, exception_handler.as_ref(), instruction_set)?;

        for (i, frame) in stack_frames.iter().enumerate() {
            let mut s = String::new();
            write!(&mut s, "Frame {}: {} @ {}", i, frame.function_name, frame.pc).unwrap();

            if frame.is_inlined {
                write!(&mut s, " inline").unwrap();
            }

            if let Some(location) = &frame.source_location {
                write!(&mut s, "\n       ").unwrap();
                write!(&mut s, "{}", location.path.to_string_lossy()).unwrap();

                if let Some(line) = location.line {
                    write!(&mut s, ":{line}").unwrap();

                    if let Some(col) = location.column {
                        match col {
                            probe_rs_debug::ColumnType::LeftEdge => {
                                write!(&mut s, ":1").unwrap();
                            }
                            probe_rs_debug::ColumnType::Column(c) => {
                                write!(&mut s, ":{c}").unwrap();
                            }
                        }
                    }
                }
            }

            info!("{}", s);
        }

        Ok(())
    }

    fn dump_state(&mut self, core: &mut Core, force: bool) -> anyhow::Result<bool> {
        core.halt(TIMEOUT)?;

        // determine if the target is handling an interupt
        let xpsr: u32 = core.read_core_reg(XPSR)?;
        let exception_number = xpsr & 0xff;
        match exception_number {
            0 => {
                //info!("No exception!");
                if force {
                    self.traceback(core)?;
                }
                Ok(false)
            }
            3 => {
                self.traceback(core)?;
                info!("Hard Fault!");

                // Get reason for hard fault
                let hfsr = core.read_word_32(0xE000_ED2C)?;

                if hfsr & (1 << 30) != 0 {
                    info!("-> configurable priority exception has been escalated to hard fault!");

                    // read cfsr
                    let cfsr = core.read_word_32(0xE000_ED28)?;

                    let ufsr = (cfsr >> 16) & 0xffff;
                    let bfsr = (cfsr >> 8) & 0xff;
                    let mmfsr = (cfsr) & 0xff;

                    if ufsr != 0 {
                        info!("\tUsage Fault     - UFSR: {:#06x}", ufsr);
                    }

                    if bfsr != 0 {
                        info!("\tBus Fault       - BFSR: {:#04x}", bfsr);

                        if bfsr & (1 << 7) != 0 {
                            // Read address from BFAR
                            let bfar = core.read_word_32(0xE000_ED38)?;
                            info!("\t Location       - BFAR: {:#010x}", bfar);
                        }
                    }

                    if mmfsr != 0 {
                        info!("\tMemManage Fault - BFSR: {:04x}", bfsr);
                    }
                }
                Ok(true)
            }
            // Ignore other exceptions for now
            _ => {
                self.traceback(core)?;
                info!("Exception {}", exception_number);
                Ok(false)
            }
        }
    }
}

fn setup_logging_channel(rtt_addr: u32, sess: &mut Session) -> anyhow::Result<Rtt> {
    const NUM_RETRIES: usize = 10; // picked at random, increase if necessary
    let mut rtt_res: Result<Rtt, probe_rs::rtt::Error> = Err(probe_rs::rtt::Error::ControlBlockNotFound);

    let memory_map = sess.target().memory_map.clone();
    let mut core = sess.core(0).unwrap();

    for try_index in 0..=NUM_RETRIES {
        rtt_res = Rtt::attach_region(&mut core, &ScanRegion::Exact(rtt_addr as _));
        match rtt_res {
            Ok(_) => {
                log::debug!("Successfully attached RTT");
                break;
            }
            Err(probe_rs::rtt::Error::ControlBlockNotFound) => {
                if try_index < NUM_RETRIES {
                    log::trace!(
                        "Could not attach because the target's RTT control block isn't initialized (yet). retrying"
                    );
                } else {
                    log::error!("Max number of RTT attach retries exceeded.");
                    return Err(anyhow!(probe_rs::rtt::Error::ControlBlockNotFound));
                }
            }
            Err(e) => {
                return Err(anyhow!(e));
            }
        }
    }

    // this block is only executed when rtt was successfully attached before
    let mut rtt = rtt_res.expect("unreachable");
    for ch in rtt.up_channels().iter() {
        log::debug!(
            "up channel {}: {:?}, buffer size {} bytes",
            ch.number(),
            ch.name(),
            ch.buffer_size()
        );
    }
    for ch in rtt.down_channels().iter() {
        log::debug!(
            "down channel {}: {:?}, buffer size {} bytes",
            ch.number(),
            ch.name(),
            ch.buffer_size()
        );
    }

    rtt.up_channels()
        .get(0)
        .ok_or_else(|| anyhow!("RTT up channel 0 not found"))?;

    Ok(rtt)
}

fn get_rtt_main_from(elf: &ElfFile) -> anyhow::Result<(Option<u32>, u32)> {
    let mut rtt = None;
    let mut main = None;

    for symbol in elf.symbols() {
        let name = match symbol.name() {
            Ok(name) => name,
            Err(_) => continue,
        };

        match name {
            "main" => main = Some(symbol.address() as u32 & !THUMB_BIT),
            "_SEGGER_RTT" => rtt = Some(symbol.address() as u32),
            _ => {}
        }
    }

    Ok((rtt, main.ok_or_else(|| anyhow!("`main` symbol not found"))?))
}

/// The contents of the vector table
#[derive(Debug)]
struct VectorTable {
    location: u32,
    // entry 0
    initial_sp: u32,
    // entry 1: Reset handler
    reset: u32,
    // entry 3: HardFault handler
    hard_fault: u32,
}
