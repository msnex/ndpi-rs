use clap::Parser;

static ARGS: std::sync::OnceLock<Args> = std::sync::OnceLock::new();

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Args {
    #[arg(short, long, help = "pcap file or device for live capture")]
    pub input: Vec<String>,
    #[arg(short, long, help = "BPF filter")]
    pub filter: Option<String>,
}

pub fn args() -> &'static Args {
    ARGS.get_or_init(|| Args::parse())
}
