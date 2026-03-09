use std::collections::BTreeMap;

pub enum FlowStatsOp {
    Add,
    Keep,
}

#[derive(Debug, Default, Clone)]
pub struct NdpiProtoStats {
    pub flow_cnt: usize,
    pub pkt_cnt: usize,
    pub pkt_bytes: usize,
    pub category: String,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub thread_id: usize,
    pub pcap_dev: String,
    pub flow_cnt: usize,
    pub pkt_cnt: usize,
    pub pkt_bytes: usize,
    pub eth_pkt_cnt: usize,
    pub eth_pkt_bytes: usize,
    pub ndpi_protos: BTreeMap<String, BTreeMap<String, NdpiProtoStats>>,
    pub ndpi_risks: BTreeMap<String, usize>,
}

impl Stats {
    pub fn print_stats(&self) {
        println!();
        println!("Thread: {}, pcap device: {}", self.thread_id, self.pcap_dev);
        println!("    Total flows: {}", self.flow_cnt);
        println!(
            "    Total packets: {}, bytes: {}",
            self.pkt_cnt, self.pkt_bytes
        );
        println!(
            "    Ethernet packets: {}, bytes: {}",
            self.eth_pkt_cnt, self.eth_pkt_bytes
        );
        println!();

        if self.ndpi_protos.len() > 0 {
            println!("    Detected Protocols:");

            for item in &self.ndpi_protos {
                // master protocol: indent 6 spaces
                println!("      {}:", item.0);
                // app protocol, protocol stats and category: indent 8 spaces
                println!(
                    "        {:<25} {:<10} {:<12} {:<18} {}",
                    "App Protocol", "Flows", "Packets", "Bytes", "Category"
                );
                println!(
                    "        {:-<25} {:-<10} {:-<12} {:-<18} {:-<25}",
                    "", "", "", "", ""
                );
                for proto_item in item.1 {
                    let proto_stats = proto_item.1;
                    println!(
                        "        {:<25} {:<10} {:<12} {:<18} {}",
                        proto_item.0,
                        proto_stats.flow_cnt,
                        proto_stats.pkt_cnt,
                        proto_stats.pkt_bytes,
                        proto_stats.category,
                    );
                }
                println!();
            }
        }

        if self.ndpi_risks.len() > 0 {
            println!("    Risk stats:");
            for risk in &self.ndpi_risks {
                println!("      {:<36} {}", risk.0, risk.1);
            }
            println!();
        }

        println!();
    }
}
