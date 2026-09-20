mod live;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};
use usbscope_capture::{Reassembler, pcapng, read_raw_header, read_record};
use usbscope_common::RAW_MAGIC;

#[derive(Parser)]
#[command(
    version,
    about = "USB capture for Linux kernels without CONFIG_USB_MON"
)]
struct Args {
    /// Read a usbscope event archive instead of capturing live USB traffic.
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    read: Option<PathBuf>,
    /// Write Wireshark-compatible pcapng; '-' writes binary data to stdout.
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    write: Option<PathBuf>,
    /// USB bus to capture (any, usb1, usb2, ...).
    #[arg(short = 'i', long = "interface", default_value = "any")]
    interface: String,
    /// Capture one device address on the selected bus.
    #[arg(long)]
    device: Option<u8>,
    /// List available USB buses.
    #[arg(short = 'D', long)]
    list_interfaces: bool,
    /// Stop after this many complete events (submission and completion count separately).
    #[arg(short = 'c', long)]
    count: Option<u64>,
    /// Stop after this many seconds.
    #[arg(long)]
    duration: Option<f64>,
    /// Ring buffer size in KiB; must be a power of two.
    #[arg(short = 'B', long, default_value_t = 16384)]
    buffer_size: u32,
    /// Preserve ring records in an archive for replay or diagnosing loss.
    #[arg(long, value_name = "FILE")]
    raw_output: Option<PathBuf>,
    /// Compiled Aya/Rust BPF object.
    #[arg(long, default_value = "target/usbscope.bpf.o")]
    bpf_object: PathBuf,
    /// Return an error if any event is incomplete or kernel capture reports loss.
    #[arg(long)]
    fail_on_loss: bool,
    /// File created once all probes are attached (for supervised capture).
    #[arg(long, hide = true)]
    ready_file: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("usbscope: {error:#}");
        std::process::exit(1);
    }
}

fn different_files(first: &Path, second: &Path) -> Result<()> {
    ensure!(first != second, "input and output must be different files");
    if let (Ok(a), Ok(b)) = (fs::metadata(first), fs::metadata(second)) {
        ensure!(
            (a.dev(), a.ino()) != (b.dev(), b.ino()),
            "input and output refer to the same file"
        );
    }
    Ok(())
}

fn output(path: &Path) -> Result<BufWriter<Box<dyn Write>>> {
    let writer: Box<dyn Write> = if path.as_os_str() == "-" {
        Box::new(io::stdout().lock())
    } else {
        Box::new(File::create(path).with_context(|| format!("creating {}", path.display()))?)
    };
    Ok(BufWriter::new(writer))
}

fn run(args: Args) -> Result<()> {
    if args.list_interfaces {
        println!("any\tAll USB buses");
        let mut buses = Vec::new();
        for entry in fs::read_dir("/sys/bus/usb/devices")? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("usb") {
                let product = fs::read_to_string(entry.path().join("product")).unwrap_or_default();
                buses.push((name, product.trim().to_owned()));
            }
        }
        buses.sort();
        for (name, product) in buses {
            println!("{name}\t{product}");
        }
        return Ok(());
    }
    ensure!(args.count != Some(0), "-c must be positive");
    ensure!(
        args.device.is_none_or(|n| n <= 127),
        "USB device address must be in 0..127"
    );
    let duration = args
        .duration
        .map(|seconds| {
            ensure!(
                seconds.is_finite() && seconds > 0.0,
                "duration must be finite and positive"
            );
            Duration::try_from_secs_f64(seconds).context("invalid duration")
        })
        .transpose()?;
    let bus = if args.interface == "any" {
        0
    } else {
        let bus: u16 = args
            .interface
            .strip_prefix("usb")
            .context("interface must be any or usbN")?
            .parse()
            .context("invalid USB bus number")?;
        ensure!(bus != 0, "USB bus numbers start at 1");
        u32::from(bus)
    };
    if let Some(raw) = &args.raw_output {
        ensure!(raw.as_os_str() != "-", "raw archive requires a file path");
        if let Some(write) = &args.write {
            different_files(raw, write)?;
        }
        if let Some(read) = &args.read {
            different_files(raw, read)?;
        }
    }
    if let (Some(read), Some(write)) = (&args.read, &args.write) {
        different_files(read, write)?;
    }
    let mut input = args
        .read
        .as_ref()
        .map(|path| -> Result<_> {
            let mut input = BufReader::new(File::open(path).context("opening input")?);
            read_raw_header(&mut input)?;
            Ok(input)
        })
        .transpose()?;
    let mut writer = args
        .write
        .as_ref()
        .map(|path| pcapng::Writer::new(output(path)?))
        .transpose()?;
    let mut raw = args
        .raw_output
        .as_ref()
        .map(|path| output(path))
        .transpose()?;
    if let Some(raw) = &mut raw {
        raw.write_all(&RAW_MAGIC)?;
    }
    let mut assembler = Reassembler::default();
    let mut written = 0;
    let mut consume = |record: &[u8]| -> Result<bool> {
        if let Some(raw) = &mut raw {
            raw.write_all(&(record.len() as u32).to_le_bytes())?;
            raw.write_all(record)?;
        }
        if let Some(mut event) = assembler.push(record)?
            && args.count.is_none_or(|limit| written < limit)
        {
            if let Some(writer) = &mut writer {
                writer.write_event(&mut event)?;
            } else {
                let m = &event.meta;
                println!(
                    "{}.{:06} {} usb{} {:03} ep={:02x} type={} status={} len={}/{} data={}",
                    m.timestamp_ns / 1_000_000_000,
                    m.timestamp_ns % 1_000_000_000 / 1000,
                    m.event_type as char,
                    m.bus,
                    m.device,
                    m.endpoint,
                    m.transfer_type,
                    m.status,
                    m.actual_len,
                    m.requested_len,
                    m.payload_len
                );
            }
            written += 1;
        }
        Ok(args.count.is_some_and(|limit| written >= limit))
    };
    let kernel = if let Some(input) = &mut input {
        while let Some(record) = read_record(input)? {
            if consume(&record)? {
                break;
            }
        }
        None
    } else {
        Some(live::capture(
            live::Options {
                object: &args.bpf_object,
                ring_kib: args.buffer_size,
                bus,
                device: args.device,
                duration,
                ready_file: args.ready_file.as_deref(),
            },
            &mut consume,
        )?)
    };
    assembler.finish();
    if let Some(writer) = &mut writer {
        writer.flush()?;
    }
    if let Some(raw) = &mut raw {
        raw.flush()?;
    }
    let stats = &assembler.stats;
    eprintln!(
        "{} events written; {} incomplete events; {} orphan records",
        written, stats.incomplete, stats.orphan_records
    );
    let mut losses = stats.incomplete + stats.orphan_records;
    if let Some(stats) = kernel {
        eprintln!(
            "kernel: {} submitted, {} completed, {} submit errors; {} ring losses, {} read errors, {} unsupported buffers, {} state errors; {} URBs still in flight at stop",
            stats.submitted,
            stats.completed,
            stats.submit_errors,
            stats.ring_losses,
            stats.read_errors,
            stats.unsupported_buffers,
            stats.state_errors,
            stats
                .submitted
                .saturating_sub(stats.completed + stats.submit_errors)
        );
        losses +=
            stats.ring_losses + stats.read_errors + stats.unsupported_buffers + stats.state_errors;
    }
    ensure!(
        !args.fail_on_loss || losses == 0,
        "capture contains lost or incomplete events"
    );
    Ok(())
}
