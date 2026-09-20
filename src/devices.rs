use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// Initial sysfs snapshot. This never sends requests to a device or fabricates
/// descriptor URBs. It complements, but does not modify, the pcapng stream.
pub fn snapshot(path: &Path) -> Result<()> {
    let mut devices = Vec::<Value>::new();
    for entry in fs::read_dir("/sys/bus/usb/devices")? {
        let entry = entry?;
        let base = entry.path();
        let attribute = |name: &str| {
            fs::read_to_string(base.join(name))
                .ok()
                .map(|s| s.trim().to_owned())
        };
        let Some(bus) = attribute("busnum") else {
            continue;
        };
        let Some(device) = attribute("devnum") else {
            continue;
        };
        let descriptors = fs::read(base.join("descriptors")).ok().map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        });
        devices.push(json!({
            "sysfs": entry.file_name().to_string_lossy(), "bus": bus, "device": device,
            "vid": attribute("idVendor"), "pid": attribute("idProduct"),
            "speed_mbps": attribute("speed"), "manufacturer": attribute("manufacturer"),
            "product": attribute("product"), "serial": attribute("serial"),
            "descriptors_hex": descriptors,
        }));
    }
    devices.sort_by_key(|v| v["sysfs"].as_str().unwrap_or_default().to_owned());
    let snapshot = json!({"format": "usbscope-device-context-v1",
        "observed_at_ns": SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos().to_string(),
        "scope": "initial sysfs snapshot; not synchronized with every URB", "devices": devices});
    let mut file = fs::File::create(path).context("creating device context")?;
    serde_json::to_writer_pretty(&mut file, &snapshot)?;
    file.write_all(b"\n")?;
    Ok(())
}
