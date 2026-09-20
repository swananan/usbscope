use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection};
use usbscope_common::{BPF_BUILD_MAGIC, CaptureConfig};

pub fn validate_object(bytes: &[u8]) -> Result<()> {
    let object = object::File::parse(bytes).context("parsing BPF object")?;
    ensure!(
        object.architecture() == object::Architecture::Bpf && object.is_little_endian(),
        "expected a little-endian eBPF object"
    );
    let info = object
        .section_by_name(".usbscope")
        .context("missing BPF build metadata; rebuild the object with scripts/build-ebpf.sh")?
        .data()?;
    ensure!(
        info.len() == 16 && info[..8] == BPF_BUILD_MAGIC,
        "invalid BPF build metadata"
    );
    let architecture = u32::from_le_bytes(info[8..12].try_into()?);
    let expected = if cfg!(target_arch = "aarch64") {
        183
    } else {
        62
    };
    ensure!(
        architecture == expected,
        "BPF object architecture mismatch: rebuild for {}",
        std::env::consts::ARCH
    );
    ensure!(
        u32::from_le_bytes(info[12..16].try_into()?) as usize == size_of::<CaptureConfig>(),
        "BPF configuration ABI mismatch: rebuild userspace and BPF together"
    );
    Ok(())
}
