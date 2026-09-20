use anyhow::{Context, Result, ensure};
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};
use usbscope_capture::{Event, pcapng};

type Writer = pcapng::Writer<BufWriter<Box<dyn Write>>>;

pub fn rotated_path(base: &Path, index: u32) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".{index:06}"));
    PathBuf::from(name)
}

pub struct CaptureOutput {
    base: PathBuf,
    writer: Writer,
    size: Option<u64>,
    seconds: Option<u64>,
    max_files: Option<u32>,
    file_index: u32,
    events: u64,
    started: Option<u64>,
}

impl CaptureOutput {
    pub fn new(
        base: &Path,
        size: Option<u64>,
        seconds: Option<u64>,
        max_files: Option<u32>,
    ) -> Result<Self> {
        let rotating = size.is_some() || seconds.is_some();
        ensure!(
            !rotating || base.as_os_str() != "-",
            "file rotation requires an output path"
        );
        ensure!(max_files.is_none() || rotating, "-W requires -C or -G");
        ensure!(
            size != Some(0) && seconds != Some(0) && max_files != Some(0),
            "rotation limits must be positive"
        );
        let writer = Self::open(base, rotating, 0)?;
        Ok(Self {
            base: base.to_owned(),
            writer,
            size,
            seconds,
            max_files,
            file_index: 0,
            events: 0,
            started: None,
        })
    }
    fn open(base: &Path, rotating: bool, index: u32) -> Result<Writer> {
        let output = if rotating {
            let path = rotated_path(base, index);
            // Rotation never overwrites an earlier capture or the input file.
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!(
                        "creating {} (rotated files must not already exist)",
                        path.display()
                    )
                })?;
            BufWriter::new(Box::new(file) as Box<dyn Write>)
        } else {
            crate::output(base)?
        };
        pcapng::Writer::new(output)
    }
    /// false means the requested file count has been reached. An event is never
    /// split across files, even if it exceeds the requested file-size target.
    pub fn write(&mut self, event: &mut Event) -> Result<bool> {
        let now = event.meta.timestamp_ns;
        let rotate = self.events != 0
            && (self
                .size
                .is_some_and(|size| self.writer.bytes_written() >= size)
                || self.seconds.is_some_and(|seconds| {
                    self.started
                        .is_some_and(|start| now.saturating_sub(start) / 1_000_000_000 >= seconds)
                }));
        if rotate {
            if self.max_files.is_some_and(|max| self.file_index + 1 >= max) {
                return Ok(false);
            }
            self.writer.flush()?;
            self.file_index = self
                .file_index
                .checked_add(1)
                .context("rotation counter exhausted")?;
            self.writer = Self::open(&self.base, true, self.file_index)?;
            self.events = 0;
            self.started = None;
        }
        self.started.get_or_insert(now);
        self.writer.write_event(event)?;
        self.events += 1;
        Ok(true)
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}
