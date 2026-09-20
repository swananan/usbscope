use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    path::PathBuf,
};
use usbscope_capture::{Reassembler, pcapng, read_raw_header, read_record};

#[derive(Parser)]
#[command(
    version,
    about = "USB capture for Linux kernels without CONFIG_USB_MON"
)]
struct Args {
    /// Read a usbscope event archive.
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    read: PathBuf,
    /// Write Wireshark-compatible pcapng; '-' writes to stdout.
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    write: PathBuf,
    /// Return an error if any event is incomplete.
    #[arg(long)]
    fail_on_loss: bool,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("usbscope: {error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    ensure!(
        args.read != args.write,
        "input and output must be different files"
    );
    let mut input = BufReader::new(File::open(&args.read).context("opening input")?);
    if args.write.as_os_str() != "-"
        && let Ok(output_meta) = std::fs::metadata(&args.write)
    {
        let input_meta = input.get_ref().metadata()?;
        ensure!(
            (input_meta.dev(), input_meta.ino()) != (output_meta.dev(), output_meta.ino()),
            "input and output refer to the same file"
        );
    }
    read_raw_header(&mut input)?;
    let output: Box<dyn Write> = if args.write.as_os_str() == "-" {
        Box::new(io::stdout().lock())
    } else {
        Box::new(File::create(&args.write).context("creating output")?)
    };
    let mut writer = pcapng::Writer::new(BufWriter::new(output))?;
    let mut assembler = Reassembler::default();
    while let Some(record) = read_record(&mut input)? {
        if let Some(mut event) = assembler.push(&record)? {
            writer.write_event(&mut event)?;
        }
    }
    assembler.finish();
    writer.flush()?;
    let stats = &assembler.stats;
    eprintln!(
        "{} events written; {} incomplete events; {} orphan records",
        stats.complete, stats.incomplete, stats.orphan_records
    );
    ensure!(
        !args.fail_on_loss || stats.incomplete + stats.orphan_records == 0,
        "capture contains lost or incomplete events"
    );
    Ok(())
}
