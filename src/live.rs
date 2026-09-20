use anyhow::{Context, Result, ensure};
use aya::{
    Btf, EbpfLoader,
    maps::{Array, PerCpuArray, RingBuf},
    programs::{FEntry, FExit, KProbe},
};
use std::{
    fs,
    os::fd::AsRawFd,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use usbscope_common::{CaptureConfig, CaptureStats};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

pub struct Options<'a> {
    pub object: &'a Path,
    pub ring_kib: u32,
    pub bus: u32,
    pub device: Option<u8>,
    pub duration: Option<Duration>,
    pub ready_file: Option<&'a Path>,
}

/// Fail closed if the post-DMA completion call site cannot be identified.
/// In particular, redacted kallsyms addresses are never accepted.
fn giveback_range() -> Result<(u64, u64)> {
    let symbols = fs::read_to_string("/proc/kallsyms").context("reading kernel symbols")?;
    let functions: Vec<_> = symbols
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let address = u64::from_str_radix(words.next()?, 16).ok()?;
            let kind = words.next()?;
            let name = words.next()?;
            matches!(kind, "t" | "T").then_some((address, name))
        })
        .collect();
    let start = functions
        .iter()
        .find(|(_, name)| *name == "__usb_hcd_giveback_urb")
        .map(|(address, _)| *address)
        .filter(|address| *address != 0)
        .context("__usb_hcd_giveback_urb address unavailable; readable kallsyms is required")?;
    let end = functions
        .iter()
        .filter_map(|(address, _)| (*address > start).then_some(*address))
        .min()
        .context("cannot determine completion function boundary")?;
    Ok((start, end))
}

fn epoch_offset() -> Result<u64> {
    let mut monotonic = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut realtime = monotonic;
    // bpf_ktime_get_ns uses CLOCK_MONOTONIC. Convert with a session offset.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotonic) } == 0,
        "reading monotonic clock failed"
    );
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime) } == 0,
        "reading wall clock failed"
    );
    let nanos = |t: libc::timespec| t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64;
    Ok(nanos(realtime).wrapping_sub(nanos(monotonic)))
}

/// The callback returns true after the requested event count is reached.
/// Stop new submissions first, then allow already submitted URBs to finish.
pub fn capture(
    options: Options<'_>,
    mut record: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<CaptureStats> {
    let ring_bytes = options
        .ring_kib
        .checked_mul(1024)
        .context("ring size overflow")?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
    ensure!(
        ring_bytes.is_power_of_two() && ring_bytes >= page,
        "-B must specify a power-of-two number of KiB, at least one page"
    );
    let (giveback_start, giveback_end) = giveback_range()?;
    let btf = Btf::from_sys_fs().context("kernel BTF is required")?;
    let mut bpf = EbpfLoader::new()
        .map_max_entries("EVENTS", ring_bytes)
        .load_file(options.object)
        .context("loading USB BPF object")?;
    let mut config =
        Array::<_, CaptureConfig>::try_from(bpf.take_map("CONFIG").context("missing CONFIG map")?)?;
    let stats = PerCpuArray::<_, CaptureStats>::try_from(
        bpf.take_map("STATS").context("missing STATS map")?,
    )?;
    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").context("missing EVENTS map")?)?;
    for (program, function) in [
        ("observe_giveback", "__usb_hcd_giveback_urb"),
        ("observe_submit", "usb_hcd_submit_urb"),
    ] {
        let probe: &mut FEntry = bpf
            .program_mut(program)
            .context("missing fentry program")?
            .try_into()?;
        probe
            .load(function, &btf)
            .with_context(|| format!("loading fentry {function}"))?;
        probe.attach()?;
    }
    let probe: &mut FExit = bpf
        .program_mut("observe_submit_error")
        .context("missing fexit program")?
        .try_into()?;
    probe
        .load("usb_hcd_submit_urb", &btf)
        .context("loading submit error probe")?;
    probe.attach()?;
    let probe: &mut KProbe = bpf
        .program_mut("observe_complete")
        .context("missing completion probe")?
        .try_into()?;
    probe.load().context("loading completion probe")?;
    probe
        .attach("usb_unanchor_urb", 0)
        .context("attaching post-DMA completion probe")?;
    let mut settings = CaptureConfig {
        epoch_offset_ns: epoch_offset()?,
        giveback_start,
        giveback_end,
        bus: options.bus,
        device: options.device.map_or(u32::MAX, u32::from),
        enabled: 1,
        reserved: 0,
    };
    INTERRUPTED.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGINT, interrupt as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, interrupt as *const () as libc::sighandler_t);
    }
    config.set(0, settings, 0)?;
    if let Some(path) = options.ready_file {
        fs::write(path, b"ready\n")?;
    }
    eprintln!(
        "listening on {}, full payload capture; Ctrl-C to stop",
        if options.bus == 0 {
            "any".to_owned()
        } else {
            format!("usb{}", options.bus)
        }
    );
    let started = Instant::now();
    let mut stop_at = None;
    let mut count_reached = false;
    loop {
        // Bound each drain batch so a busy ring cannot starve signal/deadline checks.
        for _ in 0..1024 {
            let Some(item) = ring.next() else {
                break;
            };
            ensure!(item.len() >= 24, "short kernel record");
            let size = usbscope_capture::u32_at(&item, 4) as usize;
            ensure!(
                (24..=item.len()).contains(&size),
                "invalid kernel record length"
            );
            count_reached |= record(&item[..size])?;
        }
        if stop_at.is_none()
            && (count_reached
                || INTERRUPTED.load(Ordering::Relaxed)
                || options
                    .duration
                    .is_some_and(|duration| started.elapsed() >= duration))
        {
            settings.enabled = 0;
            config.set(0, settings, 0)?;
            stop_at = Some(Instant::now() + Duration::from_millis(200));
        }
        if stop_at.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let mut poll = libc::pollfd {
            fd: ring.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 20) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    // Detach before reading counters: no more BPF writes can race this snapshot.
    drop(bpf);
    let mut total = CaptureStats::default();
    for cpu in stats.get(&0, 0)?.iter() {
        total.submitted += cpu.submitted;
        total.completed += cpu.completed;
        total.submit_errors += cpu.submit_errors;
        total.ring_losses += cpu.ring_losses;
        total.read_errors += cpu.read_errors;
        total.unsupported_buffers += cpu.unsupported_buffers;
        total.state_errors += cpu.state_errors;
        total.unmatched_completions += cpu.unmatched_completions;
    }
    // Drain records published immediately before detach.
    while let Some(item) = ring.next() {
        ensure!(item.len() >= 24, "short kernel record");
        let size = usbscope_capture::u32_at(&item, 4) as usize;
        ensure!(
            (24..=item.len()).contains(&size),
            "invalid kernel record length"
        );
        record(&item[..size])?;
    }
    Ok(total)
}
