use anyhow::{Context, Result, ensure};
use flate2::read::GzDecoder;
use std::{fs, io::Read};
use usbscope_common::{SG_ARM64_COMPACT, SG_ARM64_LEGACY, SgMemory};

fn read_config() -> Result<String> {
    if let Ok(file) = fs::File::open("/proc/config.gz") {
        let mut config = String::new();
        const MAX_CONFIG: u64 = 16 * 1024 * 1024;
        GzDecoder::new(file)
            .take(MAX_CONFIG + 1)
            .read_to_string(&mut config)
            .context("decoding /proc/config.gz")?;
        ensure!(
            config.len() as u64 <= MAX_CONFIG,
            "kernel configuration is too large"
        );
        return Ok(config);
    }
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
    fs::read_to_string(format!("/boot/config-{}", release.trim()))
        .context("reading the running kernel configuration")
}

pub fn arm64_memory(config: &str, page_size: u32, release: &str) -> Option<SgMemory> {
    let mut version = release.trim().split('.');
    let major: u32 = version.next()?.parse().ok()?;
    let minor: u32 = version.next()?.parse().ok()?;
    if (major, minor) < (5, 17) {
        return None;
    }
    // VMEMMAP_START is a preprocessor constant, not a BTF-relocatable field.
    // Upstream 6.9 moved the region below -1 GiB and stopped rounding page size.
    let layout = if (major, minor) >= (6, 9) {
        SG_ARM64_COMPACT
    } else {
        SG_ARM64_LEGACY
    };
    let value = |key: &str| {
        config.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name == key).then_some(value)
        })
    };
    if value("CONFIG_ARM64") != Some("y")
        || value("CONFIG_SPARSEMEM_VMEMMAP") != Some("y")
        || value("CONFIG_KASAN_SW_TAGS") == Some("y")
        || value("CONFIG_KASAN_HW_TAGS") == Some("y")
    {
        return None;
    }
    let (page_shift, page_option, valid_bits): (_, _, &[u32]) = match page_size {
        4096 => (12, "CONFIG_ARM64_4K_PAGES", &[39, 48]),
        16384 => (14, "CONFIG_ARM64_16K_PAGES", &[36, 47, 48]),
        65536 => (16, "CONFIG_ARM64_64K_PAGES", &[42, 48, 52]),
        _ => return None,
    };
    let va_bits = value("CONFIG_ARM64_VA_BITS")?.parse().ok()?;
    if value(page_option) != Some("y") || !valid_bits.contains(&va_bits) {
        return None;
    }
    Some(SgMemory {
        page_shift,
        va_bits,
        layout,
        ..SgMemory::default()
    })
}

pub fn arm64_runtime_memory(page_size: u32) -> SgMemory {
    match read_config()
        .and_then(|config| Ok((config, fs::read_to_string("/proc/sys/kernel/osrelease")?)))
    {
        Ok((config, release)) => {
            if let Some(memory) = arm64_memory(&config, page_size, &release) {
                return memory;
            }
            eprintln!("arm64 SG capture unavailable: unsupported kernel memory configuration");
        }
        Err(error) => eprintln!("arm64 SG capture unavailable: {error:#}"),
    }
    SgMemory::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "CONFIG_ARM64=y\nCONFIG_SPARSEMEM_VMEMMAP=y\nCONFIG_ARM64_64K_PAGES=y\nCONFIG_ARM64_VA_BITS=48\n";

    #[test]
    fn rejects_a_configuration_that_does_not_match_the_running_page_size() {
        assert!(arm64_memory(CONFIG, 4096, "6.6.142").is_none());
        assert!(arm64_memory(CONFIG, 65536, "6.6.142").is_some());
        assert!(arm64_memory(&CONFIG.replace("=48", "=39"), 65536, "6.6.142").is_none());
    }

    #[test]
    fn refuses_missing_layout_information_and_tagged_kernel_memory() {
        assert!(arm64_memory("CONFIG_ARM64=y\n", 65536, "6.6.142").is_none());
        assert!(
            arm64_memory(&CONFIG.replace("VMEMMAP=y", "VMEMMAP=n"), 65536, "6.6.142").is_none()
        );
        for option in ["CONFIG_KASAN_SW_TAGS=y", "CONFIG_KASAN_HW_TAGS=y"] {
            assert!(arm64_memory(&format!("{CONFIG}{option}\n"), 65536, "6.6.142").is_none());
        }
    }

    #[test]
    fn selects_the_upstream_layout_across_the_6_9_boundary() {
        for release in ["6.6.142", "6.8.0-custom"] {
            assert_eq!(
                arm64_memory(CONFIG, 65536, release).unwrap().layout,
                SG_ARM64_LEGACY
            );
        }
        for release in ["6.9.0", "6.12.110", "6.18.52", "7.2.6-custom"] {
            assert_eq!(
                arm64_memory(CONFIG, 65536, release).unwrap().layout,
                SG_ARM64_COMPACT
            );
        }
        for release in ["", "unknown", "5.10.0", "6.x.0"] {
            assert!(arm64_memory(CONFIG, 65536, release).is_none());
        }
    }
}
