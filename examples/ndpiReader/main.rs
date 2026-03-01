use crate::dpi::WorkFlow;
use crate::stats::Stats;
use anyhow::Result;
use pcap::{Capture, Device};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod args;
mod dpi;
mod stats;

static RUNNING: std::sync::OnceLock<AtomicBool> = std::sync::OnceLock::new();
static PCAP_BREAK_HANDLES: OnceLock<Mutex<Vec<pcap::BreakLoop>>> = OnceLock::new();
static THREAD_STATS: OnceLock<Mutex<Vec<Stats>>> = OnceLock::new();

#[derive(Default)]
struct PacketStats {
    thread_id: usize,
    ts_sec: i64,
    pkts: usize,
    running: bool,
}

fn insert_pcap_break_handle(handle: pcap::BreakLoop) {
    PCAP_BREAK_HANDLES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push(handle);
}

fn insert_thread_stats(stats: Stats) {
    THREAD_STATS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap()
        .push(stats);
}

fn print_stats() {
    if let Some(v) = THREAD_STATS.get() {
        let mut vec = v.lock().unwrap();
        vec.sort_by(|a, b| a.thread_id.cmp(&b.thread_id));

        for stats in vec.iter() {
            stats.print_stats();
        }
    }
}

fn pcap_offline(
    thread_id: usize,
    tx: mpsc::Sender<PacketStats>,
    args: &args::Args,
    file: &str,
) -> Result<()> {
    let mut workflow = WorkFlow::new()?;
    workflow.stats.thread_id = thread_id;
    workflow.stats.pcap_dev = file.to_string();

    let mut capture = Capture::from_file(file).unwrap();
    // bpf filter
    if let Some(ref filter) = args.filter {
        capture.filter(&filter, true)?;
    }
    let break_handle = capture.breakloop_handle();
    insert_pcap_break_handle(break_handle);

    while let Ok(packet) = capture.next_packet() {
        let _ = workflow.process(&packet);
        if args.verbose {
            tx.send(PacketStats {
                thread_id,
                ts_sec: packet.header.ts.tv_sec,
                pkts: workflow.stats.pkt_cnt,
                running: true,
            })
            .unwrap();
        }
    }

    workflow.finalize_stats();
    insert_thread_stats(workflow.stats);

    Ok(())
}

fn pcap_live(
    thread_id: usize,
    tx: mpsc::Sender<PacketStats>,
    args: &args::Args,
    dev: Device,
) -> Result<()> {
    let mut workflow = WorkFlow::new()?;
    workflow.stats.thread_id = thread_id;
    workflow.stats.pcap_dev = dev.name.clone();

    let mut inactive = Capture::from_device(dev)?;
    if args.promisc_mode {
        inactive = inactive.promisc(true);
    }
    if args.immediate_mode {
        inactive = inactive.immediate_mode(true);
    }
    inactive = inactive.timeout(args.timeout);

    let mut active = inactive.open()?.setnonblock()?;
    // bpf filter
    if let Some(ref filter) = args.filter {
        active.filter(&filter, true)?;
    }

    let break_handle = active.breakloop_handle();
    insert_pcap_break_handle(break_handle);

    while crate::RUNNING.get().unwrap().load(Ordering::SeqCst) {
        match active.next_packet() {
            Ok(packet) => {
                let _ = workflow.process(&packet);
                if args.verbose {
                    tx.send(PacketStats {
                        thread_id,
                        ts_sec: packet.header.ts.tv_sec,
                        pkts: workflow.stats.pkt_cnt,
                        running: true,
                    })
                    .unwrap();
                }
            }
            Err(err) => match err {
                pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets => {
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    workflow.evict_idle_flow(now_secs);
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                _ => {}
            },
        }
    }

    workflow.finalize_stats();
    insert_thread_stats(workflow.stats);

    Ok(())
}

fn init_ctrlc() -> Result<()> {
    let _ = RUNNING.set(AtomicBool::new(true));

    ctrlc::set_handler(move || {
        // println!("Received termination signal to exit");
        let r = RUNNING.get();
        if let Some(r) = r {
            r.store(false, Ordering::SeqCst);
        } else {
            let _ = RUNNING.set(AtomicBool::new(false));
        }

        if let Some(break_handles) = PCAP_BREAK_HANDLES.get() {
            break_handles
                .lock()
                .unwrap()
                .iter()
                .for_each(|handle| handle.breakloop());
        }
    })?;

    Ok(())
}

fn packet_stats_thread_start(args: &args::Args, rx: mpsc::Receiver<PacketStats>, threads: usize) {
    if !args.verbose {
        return;
    }

    if threads == 0 {
        return;
    }
    let mut stats_ts = 0;
    let mut packet_stats = vec![0; threads];

    while let Ok(stats) = rx.recv() {
        if !stats.running {
            break;
        }
        packet_stats[stats.thread_id] = stats.pkts;
        if stats.ts_sec > stats_ts {
            stats_ts = stats.ts_sec;
            let mut total_pkts = 0;
            for i in 0..threads {
                total_pkts += packet_stats[i];
            }
            print!("\rGot Packets: {}", total_pkts);
            std::io::stdout().flush().unwrap();
        }
    }

    let mut total_pkts = 0;
    for i in 0..threads {
        total_pkts += packet_stats[i];
    }
    println!();
    println!("Got Packets: {}", total_pkts);
}

fn packet_stats_thread_stop(args: &args::Args, tx: mpsc::Sender<PacketStats>, threads: usize) {
    if threads == 0 {
        return;
    }

    if args.verbose {
        tx.send(PacketStats {
            thread_id: 0,
            ts_sec: 0,
            pkts: 0,
            running: false,
        })
        .unwrap();
    }
}

fn main() -> Result<()> {
    let args = args::args();

    dpi::ndpi_version_info();
    init_ctrlc()?;

    if args.input.is_empty() {
        return Err(anyhow::anyhow!("No pcap device or file specified"));
    }

    let threads = args.input.len();
    let mut thread_handles = Vec::new();
    let (tx, rx) = mpsc::channel::<PacketStats>();

    // thread spawn
    for item in args.input.iter().enumerate() {
        let id = item.0;
        let input = item.1;

        if input.contains('/') || input.contains('.') {
            // file
            let thread_tx = tx.clone();
            let name = format!("offline-{}", id);

            let offline_handle = thread::Builder::new()
                .name(name)
                .spawn(move || pcap_offline(id, thread_tx, &args, &input))?;
            thread_handles.push(offline_handle);
        } else {
            // device
            let devs = Device::list()?;
            if let Some(dev) = devs
                .iter()
                .find(|dev| &dev.name == input && dev.flags.is_running())
            {
                let pcap_dev = dev.clone();
                let thread_tx = tx.clone();
                let name = format!("live-{}", id);

                let live_handle = thread::Builder::new()
                    .name(name)
                    .spawn(move || pcap_live(id, thread_tx, &args, pcap_dev))?;
                thread_handles.push(live_handle);
            } else {
                eprintln!("pcap device is not found or not running: {}", input);
            }
        }
    }

    let packet_stats_handle =
        thread::Builder::new()
            .name("stats".to_string())
            .spawn(move || {
                packet_stats_thread_start(&args, rx, threads);
            })?;

    // thread join
    thread_handles.into_iter().for_each(|handle| {
        let thread_name = handle
            .thread()
            .name()
            .unwrap_or_else(|| "unknown")
            .to_string();
        if let Err(_) = handle.join() {
            eprintln!("Can't join thread: {}", thread_name);
        }
    });

    packet_stats_thread_stop(&args, tx, threads);
    packet_stats_handle.join().unwrap();

    print_stats();

    Ok(())
}
