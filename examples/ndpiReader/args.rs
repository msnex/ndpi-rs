use clap::Parser;

static ARGS: std::sync::OnceLock<Args> = std::sync::OnceLock::new();

#[derive(Debug, Clone, clap::Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Args {
    #[arg(short, help = "pcap file or device for capture")]
    pub input: Vec<String>,
    #[arg(short, long, help = "bpf filter")]
    pub filter: Option<String>,
    #[arg(short, long, help = "set promiscuous mode for actived capture")]
    pub promisc_mode: bool,
    #[arg(long, help = "set immediate mode for actived capture")]
    pub immediate_mode: bool,
    #[arg(
        short,
        long,
        default_value_t = 100,
        help = "set read timeout(ms) for actived capture"
    )]
    pub timeout: i32,
    #[arg(short, long, help = "print packet statistics")]
    pub verbose: bool,
}

pub fn args() -> &'static Args {
    ARGS.get_or_init(|| Args::parse())
}
