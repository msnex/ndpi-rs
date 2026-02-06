use ndpi_rs::ndpi_main;

fn main() {
    let version = ndpi_main::rs_ndpi_revision();
    println!("ndpi version: {}", version);
}
