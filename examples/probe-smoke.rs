//! P0 kernel test: prove CO-RE reads actual USB metadata into the ring.
use anyhow::{Context, Result, bail};
use aya::{
    Btf, Ebpf,
    maps::{Array, RingBuf},
    programs::FEntry,
};
use std::{
    fs, thread,
    time::{Duration, Instant},
};
use usbscope_capture::decode_meta;
use usbscope_common::CaptureConfig;

fn main() -> Result<()> {
    let object = std::env::args()
        .nth(1)
        .context("expected BPF object path")?;
    let btf = Btf::from_sys_fs()?;
    let mut bpf = Ebpf::load_file(object)?;
    let program: &mut FEntry = bpf
        .program_mut("observe_submit")
        .context("missing probe")?
        .try_into()?;
    program.load("usb_hcd_submit_urb", &btf)?;
    program.attach()?;
    let mut config = Array::<_, CaptureConfig>::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config.set(
        0,
        CaptureConfig {
            enabled: 1,
            device: u32::MAX,
            ..CaptureConfig::default()
        },
        0,
    )?;
    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").context("missing ring")?)?;
    fs::write("/tmp/probe-ready", b"ready")?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        while let Some(record) = ring.next() {
            if record.len() < 96 || record[2..4] != [1, 0] {
                continue;
            }
            let meta = decode_meta(&record[24..96])?;
            if meta.device > 1 && meta.transfer_type == 2 && meta.setup[1] == 6 {
                println!(
                    "OBSERVED bus={} dev={} vid={:04x} pid={:04x} len={} setup={:02x?}",
                    meta.bus, meta.device, meta.vid, meta.pid, meta.requested_len, meta.setup
                );
                // The fixture supplies the expected identity independently through usbfs.
                fs::write(
                    "/tmp/probe-observed",
                    format!(
                        "{} {} {:04x} {:04x} {}\n",
                        meta.bus, meta.device, meta.vid, meta.pid, meta.requested_len
                    ),
                )?;
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    bail!("probe attached but did not observe a device descriptor request")
}
