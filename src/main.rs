use ndpi_rs::version::NdpiVersion;

fn main() {
    let version = NdpiVersion::new();
    println!(
        "ndpi revision: {}, api version: {}, gcrypt version: {}",
        version.ndpi_revision.unwrap(),
        version.api_version,
        version.gcrypt_version.unwrap()
    );
}
