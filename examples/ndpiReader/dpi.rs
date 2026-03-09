use crate::stats::{FlowStatsOp, NdpiProtoStats, Stats};
use anyhow::Result;
use etherparse::EtherType;
use etherparse::IpNumber;
use etherparse::LinkExtSlice;
use etherparse::LinkSlice;
use etherparse::NetSlice;
use etherparse::SlicedPacket;
use etherparse::TransportSlice;
use ndpi_rs::NdpiDetection;
use ndpi_rs::NdpiFlow;
use ndpi_rs::NdpiVersion;
use ndpi_rs::flow::NDPI_FLOW_BEGINNING_UNKNOWN;
use ndpi_rs::flow::NDPI_IN_PKT_DIR_UNKNOWN;
use ndpi_rs::flow::NdpiFlowInputInfo;
use ndpi_rs::types::NdpiProtocol;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const WHEEL_SIZE: usize = 1024;
const REFRESH_GRANULARITY: u64 = 1; // seconds

#[derive(Debug, Default)]
pub struct FlowHashKey {
    vlan: [u16; 2],
    addrs: [[u8; 16]; 2],
    ports: [u16; 2],
    proto: u8,
}

impl FlowHashKey {
    const HASH_SEED: rapidhash::v3::RapidSecrets = rapidhash::v3::RapidSecrets::seed(0xa1b23c4d);

    pub fn from_sliced_packet(packet: &SlicedPacket) -> Option<Self> {
        if packet.link.is_none() {
            return None;
        }
        let link = packet.link.as_ref().unwrap();

        // ethernet
        match link {
            LinkSlice::Ethernet2(_) => {}
            _ => return None,
        }

        let mut flow_hash_key = FlowHashKey::default();

        // vlan
        let mut idx = 0;
        for ext in packet.link_exts.iter() {
            if let LinkExtSlice::Vlan(vlan) = ext {
                if idx >= 2 {
                    break;
                }
                flow_hash_key.vlan[idx] = vlan.vlan_identifier().value();
                idx += 1;
            }
        }

        if let Some(net) = packet.net.as_ref() {
            match net {
                NetSlice::Ipv4(ipv4) => {
                    let src_ip = ipv4.header().source();
                    let dst_ip = ipv4.header().destination();
                    // IPv4-mapped IPv6 address
                    if src_ip > dst_ip {
                        flow_hash_key.addrs[0] = [
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, src_ip[0], src_ip[1],
                            src_ip[2], src_ip[3],
                        ];
                        flow_hash_key.addrs[1] = [
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, dst_ip[0], dst_ip[1],
                            dst_ip[2], dst_ip[3],
                        ];
                    } else {
                        flow_hash_key.addrs[1] = [
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, src_ip[0], src_ip[1],
                            src_ip[2], src_ip[3],
                        ];
                        flow_hash_key.addrs[0] = [
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, dst_ip[0], dst_ip[1],
                            dst_ip[2], dst_ip[3],
                        ];
                    }
                    flow_hash_key.proto = ipv4.header().protocol().0;
                }
                NetSlice::Ipv6(ipv6) => {
                    let src_ip = ipv6.header().source();
                    let dst_ip = ipv6.header().destination();
                    if src_ip > dst_ip {
                        flow_hash_key.addrs[0] = src_ip;
                        flow_hash_key.addrs[1] = dst_ip;
                    } else {
                        flow_hash_key.addrs[1] = src_ip;
                        flow_hash_key.addrs[0] = dst_ip;
                    }
                    flow_hash_key.proto = ipv6.header().next_header().0;
                }
                _ => {
                    return None;
                }
            }
        }

        // transport
        if let Some(transport) = packet.transport.as_ref() {
            match transport {
                TransportSlice::Tcp(tcp) => {
                    let src_port = tcp.source_port();
                    let dst_port = tcp.destination_port();
                    if src_port > dst_port {
                        flow_hash_key.ports[0] = src_port;
                        flow_hash_key.ports[1] = dst_port;
                    } else {
                        flow_hash_key.ports[1] = src_port;
                        flow_hash_key.ports[0] = dst_port;
                    }
                }
                TransportSlice::Udp(udp) => {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();
                    if src_port > dst_port {
                        flow_hash_key.ports[0] = src_port;
                        flow_hash_key.ports[1] = dst_port;
                    } else {
                        flow_hash_key.ports[1] = src_port;
                        flow_hash_key.ports[0] = dst_port;
                    }
                }
                _ => {
                    return None;
                }
            }
        }

        Some(flow_hash_key)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }

    #[inline]
    pub fn get_hash(&self) -> u64 {
        let bytes = self.as_bytes();
        let h = rapidhash::v3::rapidhash_v3_seeded(&bytes, &Self::HASH_SEED);
        h
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum TcpState {
    New,
    Est,
    Fin,
    Closed,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, PartialEq)]
pub enum FlowState {
    #[default]
    None,
    Tcp(TcpState),
    Udp,
}

pub struct Flow {
    pub flow_hash: u64,
    pub last_sec: u64,
    pub expire_tick: u64,
    pub flow_state: FlowState,
    pub pkt_cnt: usize,
    pub pkt_bytes: usize,
    pub detected: bool,
    pub giveup: bool,
    pub ndpi_flow: NdpiFlow,
    pub detected_proto: NdpiProtocol,
    pub guessed_proto: NdpiProtocol,
}

impl Flow {
    pub fn new() -> Result<Self> {
        let ndpi_flow = NdpiFlow::new()?;

        Ok(Self {
            flow_hash: 0,
            last_sec: 0,
            expire_tick: 0,
            flow_state: FlowState::default(),
            pkt_cnt: 0,
            pkt_bytes: 0,
            detected: false,
            giveup: false,
            ndpi_flow,
            detected_proto: NdpiProtocol::default(),
            guessed_proto: NdpiProtocol::default(),
        })
    }

    pub fn update_flow_state(&mut self, packet: &SlicedPacket, proto: u8) {
        if let FlowState::None = self.flow_state {
            if proto == IpNumber::TCP.0 {
                self.flow_state = FlowState::Tcp(TcpState::New);
            } else if proto == IpNumber::UDP.0 {
                self.flow_state = FlowState::Udp;
            }
            return;
        }
        // update tcp state
        if let Some(transport) = packet.transport.as_ref() {
            if let TransportSlice::Tcp(tcp) = transport {
                if tcp.rst() {
                    self.flow_state = FlowState::Tcp(TcpState::Closed);
                    return;
                }

                match self.flow_state {
                    FlowState::Tcp(TcpState::New) => {
                        if tcp.ack() || tcp.psh() {
                            self.flow_state = FlowState::Tcp(TcpState::Est);
                        }
                    }
                    FlowState::Tcp(TcpState::Est) => {
                        if tcp.fin() {
                            self.flow_state = FlowState::Tcp(TcpState::Fin);
                        }
                    }
                    FlowState::Tcp(TcpState::Fin) => {
                        if tcp.fin() {
                            self.flow_state = FlowState::Tcp(TcpState::Closed);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

struct TimingWheel {
    slots: Vec<Vec<u64>>,
    last_tick: u64,
}

impl TimingWheel {
    #[inline]
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        TimingWheel {
            slots: vec![Vec::with_capacity(1024); WHEEL_SIZE],
            last_tick: now,
        }
    }

    #[inline]
    fn insert(&mut self, expire: u64, flow_hash: u64) {
        let slot = (expire as usize) & (WHEEL_SIZE - 1);
        self.slots[slot].push(flow_hash);
    }
}

#[derive(Debug)]
pub struct FlowTimeoutTcpCfg {
    pub new: u64,
    pub est: u64,
    pub fin: u64,
    pub closed: u64,
}

#[derive(Debug)]
pub struct FlowTimeoutCfg {
    pub tcp: FlowTimeoutTcpCfg,
    pub udp: u64,
    pub default: u64,
}

pub struct FlowTable {
    flows: HashMap<u64, Flow>,
    wheel: TimingWheel,
    policy: FlowTimeoutCfg,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            wheel: TimingWheel::new(),
            policy: FlowTimeoutCfg {
                tcp: FlowTimeoutTcpCfg {
                    new: 30,
                    est: 300,
                    fin: 10,
                    closed: 5,
                },
                udp: 60,
                default: 5,
            },
        }
    }

    pub fn get_flow_mut(&mut self, flow_hash: u64) -> Option<&mut Flow> {
        self.flows.get_mut(&flow_hash)
    }

    pub fn insert_flow(&mut self, flow_hash: u64, flow: Flow) {
        self.flows.insert(flow_hash, flow);
    }

    pub fn evict_flow(&mut self, flow_hash: u64) {
        let _ = self.flows.remove(&flow_hash);
    }

    pub fn update_flow_tick(&mut self, flow_hash: u64, ts_sec: u64) {
        if let Some(flow) = self.flows.get_mut(&flow_hash) {
            let timeout = match &flow.flow_state {
                FlowState::Tcp(tcp_state) => match tcp_state {
                    TcpState::New => self.policy.tcp.new,
                    TcpState::Est => self.policy.tcp.est,
                    TcpState::Fin => self.policy.tcp.fin,
                    TcpState::Closed => self.policy.tcp.closed,
                },
                FlowState::Udp => self.policy.udp,
                FlowState::None => self.policy.default,
            };
            if ts_sec > flow.last_sec {
                flow.last_sec = ts_sec;
            }
            let expire = flow.last_sec + timeout;

            if expire < flow.expire_tick || expire - flow.expire_tick >= REFRESH_GRANULARITY {
                // println!(
                //     "update flow hash: {}, state: {:?}, expire tick: {} -> {}",
                //     flow.flow_hash, flow.flow_state, flow.expire_tick, expire
                // );
                flow.expire_tick = expire;
                self.wheel.insert(expire, flow_hash);
            }
        }
    }
}

pub struct WorkFlow {
    detection: NdpiDetection,
    // TODO: flow timeout implementation
    flow_table: FlowTable,
    pub stats: Stats,
    last_evict_tick: u64,
}

impl WorkFlow {
    pub fn new() -> Result<Self> {
        let mut detection = NdpiDetection::new(None)?;
        detection.finalize()?;

        Ok(Self {
            detection,
            flow_table: FlowTable::new(),
            stats: Stats::default(),
            last_evict_tick: 0,
        })
    }

    fn ndpi_stats_update(
        detection: &NdpiDetection,
        flow: &Flow,
        flow_op: FlowStatsOp,
        ndpi_proto: &NdpiProtocol,
        stats: &mut Stats,
    ) {
        let master_proto = detection
            .get_protocol_name(ndpi_proto.master_protocol)
            .to_string_lossy();

        let app_proto = detection
            .get_protocol_name(ndpi_proto.app_protocol)
            .to_string_lossy();

        let category_name = detection
            .get_protocol_category_name(ndpi_proto.category)
            .to_string_lossy();
        let category = category_name.to_string();

        let master_protocol = master_proto.to_string();
        let app_protocol = app_proto.to_string();

        if let Some(proto_stats) = stats.ndpi_protos.get_mut(&master_protocol) {
            if let Some(proto_item) = proto_stats.get_mut(&app_protocol) {
                // update
                if let FlowStatsOp::Add = flow_op {
                    proto_item.flow_cnt += 1;
                }
                proto_item.pkt_cnt = flow.pkt_cnt;
                proto_item.pkt_bytes = flow.pkt_bytes;
            } else {
                // new
                proto_stats.insert(
                    app_protocol,
                    NdpiProtoStats {
                        flow_cnt: 1,
                        pkt_cnt: flow.pkt_cnt,
                        pkt_bytes: flow.pkt_bytes,
                        category,
                    },
                );
            }
        } else {
            // new
            let mut proto_stats = BTreeMap::new();
            proto_stats.insert(
                app_protocol,
                NdpiProtoStats {
                    flow_cnt: 1,
                    pkt_cnt: flow.pkt_cnt,
                    pkt_bytes: flow.pkt_bytes,
                    category,
                },
            );
            stats.ndpi_protos.insert(master_protocol, proto_stats);
        }

        if flow.ndpi_flow.has_risk() {
            let risk_strs = flow.ndpi_flow.get_risk_str_vec();
            for risk_str in risk_strs {
                let risk = risk_str.to_string_lossy().to_string();
                if let Some(flows) = stats.ndpi_risks.get_mut(&risk) {
                    if let FlowStatsOp::Add = flow_op {
                        *flows += 1;
                    }
                } else {
                    stats.ndpi_risks.insert(risk, 1);
                }
            }
        }
    }

    pub fn evict_idle_flow(&mut self, now_secs: u64) {
        if now_secs > self.last_evict_tick && now_secs - self.last_evict_tick >= 5 {
            self.last_evict_tick = now_secs;
            Self::evict_flow_table(
                &self.detection,
                &mut self.flow_table,
                &mut self.stats,
                now_secs,
            );
        }
    }

    fn evict_flow_table(
        detection: &NdpiDetection,
        flow_table: &mut FlowTable,
        stats: &mut Stats,
        now_secs: u64,
    ) {
        while flow_table.wheel.last_tick < now_secs {
            flow_table.wheel.last_tick += 1;
            let slot = flow_table.wheel.last_tick as usize & (WHEEL_SIZE - 1);

            let batches = flow_table.wheel.slots[slot].len();
            if batches == 0 {
                continue;
            }
            let mut expired = Vec::with_capacity(batches);
            std::mem::swap(&mut expired, &mut flow_table.wheel.slots[slot]);

            for flow_hash in expired {
                if let Some(flow) = flow_table.get_flow_mut(flow_hash) {
                    if flow.expire_tick <= now_secs {
                        // println!(
                        //     "evict flow hash: {}, pkts: {}, bytes: {}, expire_tick: {}, detected: {}, giveup: {}",
                        //     flow.flow_hash,
                        //     flow.pkt_cnt,
                        //     flow.pkt_bytes,
                        //     flow.expire_tick,
                        //     flow.detected,
                        //     flow.giveup
                        // );
                        if !flow.detected && !flow.giveup {
                            Self::ndpi_stats_update(
                                detection,
                                &flow,
                                FlowStatsOp::Add,
                                &flow.guessed_proto,
                                stats,
                            );
                        }
                        flow_table.evict_flow(flow_hash);
                    }
                }
            }
        }
    }

    fn dpi_detect(
        &mut self,
        proto: u8,
        flow_hash: u64,
        sliced_pkt: &SlicedPacket,
        pkt_bytes: usize,
        ip_pkt: &[u8],
        ip_pkt_len: u16,
        packet_ms: u64,
    ) -> Result<()> {
        let (detection, flow_table, stats) =
            (&mut self.detection, &mut self.flow_table, &mut self.stats);

        let flow = if let Some(f) = flow_table.get_flow_mut(flow_hash) {
            f
        } else {
            stats.flow_cnt += 1;
            let mut f = Flow::new()?;
            f.flow_hash = flow_hash;
            flow_table.insert_flow(flow_hash, f);
            flow_table.get_flow_mut(flow_hash).unwrap()
        };

        flow.pkt_cnt += 1;
        flow.pkt_bytes += pkt_bytes;
        flow.update_flow_state(&sliced_pkt, proto);

        if flow.detected || flow.giveup {
            if flow.detected {
                Self::ndpi_stats_update(
                    detection,
                    &flow,
                    FlowStatsOp::Keep,
                    &flow.detected_proto,
                    stats,
                );
            } else {
                Self::ndpi_stats_update(
                    detection,
                    &flow,
                    FlowStatsOp::Keep,
                    &flow.guessed_proto,
                    stats,
                );
            }
            return Ok(());
        }

        let mut input_info =
            NdpiFlowInputInfo::new(NDPI_IN_PKT_DIR_UNKNOWN, NDPI_FLOW_BEGINNING_UNKNOWN);

        flow.detected_proto = detection.process_packet(
            &mut flow.ndpi_flow,
            Some(&mut input_info),
            ip_pkt,
            ip_pkt_len,
            packet_ms,
        );
        if flow.detected_proto.protocol_detected() {
            flow.detected = true;
            Self::ndpi_stats_update(
                detection,
                &flow,
                FlowStatsOp::Add,
                &flow.detected_proto,
                stats,
            );
            return Ok(());
        }

        let num_processed_pkts = flow.ndpi_flow.num_processed_pkts();
        if num_processed_pkts >= 256 && !flow.detected {
            flow.guessed_proto = detection.giveup(&mut flow.ndpi_flow);
            flow.giveup = true;
            Self::ndpi_stats_update(
                detection,
                &flow,
                FlowStatsOp::Add,
                &flow.guessed_proto,
                stats,
            );
        }

        Ok(())
    }

    pub fn process(&mut self, packet: &pcap::Packet) -> Result<()> {
        let pkt_bytes = packet.data.len();
        self.stats.pkt_cnt += 1;
        self.stats.pkt_bytes += pkt_bytes;

        let packet_ms = packet.header.ts.tv_sec * 1000 + packet.header.ts.tv_usec / 1000;

        if let Ok(sliced_packet) = SlicedPacket::from_ethernet(&packet.data) {
            self.stats.eth_pkt_cnt += 1;
            self.stats.eth_pkt_bytes += pkt_bytes;

            if let Some(eth_payload) = sliced_packet.ether_payload() {
                let eth_type = eth_payload.ether_type;
                if eth_type != EtherType::IPV4 && eth_type != EtherType::IPV6 {
                    return Ok(());
                }

                let ip_pkt = eth_payload.payload;
                let ip_pkt_len = ip_pkt.len() as u16;

                let flow_hash_key = FlowHashKey::from_sliced_packet(&sliced_packet);
                if flow_hash_key.is_none() {
                    return Err(anyhow::anyhow!("Can't generate flow hash"));
                }
                let hash_key = flow_hash_key.unwrap();
                let flow_hash = hash_key.get_hash();

                self.dpi_detect(
                    hash_key.proto,
                    flow_hash,
                    &sliced_packet,
                    pkt_bytes,
                    ip_pkt,
                    ip_pkt_len,
                    packet_ms as u64,
                )?;

                let ts_sec = packet_ms / 1000;
                self.flow_table.update_flow_tick(flow_hash, ts_sec as u64);
                Self::evict_flow_table(
                    &self.detection,
                    &mut self.flow_table,
                    &mut self.stats,
                    ts_sec as u64,
                );
            }
        }
        Ok(())
    }

    pub fn finalize_stats(&mut self) {
        for item in &self.flow_table.flows {
            let flow = item.1;
            if flow.detected || flow.giveup {
                continue;
            }

            Self::ndpi_stats_update(
                &self.detection,
                &flow,
                FlowStatsOp::Add,
                &flow.guessed_proto,
                &mut self.stats,
            );
        }
    }
}

pub fn ndpi_version_info() {
    let version = NdpiVersion::new();
    let revision = match &version.ndpi_revision {
        Some(v) => &v,
        None => "none",
    };
    let gcrypt_version = match &version.gcrypt_version {
        Some(v) => &v,
        None => "none",
    };

    println!(
        "ndpi revision: {}, api version: {}, gcrypt version: {}",
        revision, version.api_version, gcrypt_version
    );
}
