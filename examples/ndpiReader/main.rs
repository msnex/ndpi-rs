use ndpi_rs::NdpiVersion;

mod args;

fn main() {
    let version = NdpiVersion::new();
    println!(
        "ndpi revision: {}, api version: {}, gcrypt version: {}",
        version.ndpi_revision.unwrap(),
        version.api_version,
        version.gcrypt_version.unwrap()
    );

    let args = args::args();
    println!("{:?}", args);

    if args.input.is_empty() {
        println!("No pcap file or device specified");
        return;
    }
}
