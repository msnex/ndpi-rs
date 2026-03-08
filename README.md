# ndpi-rs: Safe Rust Bindings for nDPI

`ndpi-rs` provides safe, idiomatic Rust bindings for the [nDPI (Deep Packet Inspection)](https://github.com/ntop/nDPI) library. This crate enables Rust applications to perform high-performance network traffic analysis and packet classification with minimal overhead.

**⚠️ Warning**: This project is currently in the early stages of development; consequently, APIs are subject to change, and certain features remain incomplete. Deployment in production environments is not recommended at this time.

## Build

### libndpi

Reference: https://github.com/ntop/nDPI/blob/dev/README.md

### ndpi-rs

This crate use `pkg-config` to locate `libndpi` library.

```bash
# build crate
cargo build --release

# build example application
cargo build --examples
```

## Example Application

The crate includes example application:

```bash
# Run the ndpiReader example
cargo run --example ndpiReader -- --help

# Run with a PCAP file
cargo run --example ndpiReader -- -i sample.pcap

# Run with live network interface
cargo run --example ndpiReader -- -i ens160 -i ens192
```

## Version Compatibility

| ndpi-rs | libndpi | Rust     |
| ------- | ------- | -------- |
| 0.1.x   | ≥ 5.0.0 | ≥ 1.92.0 |

**Note**: The `ndpi-rs` crate itself is MIT licensed, but it depends on `libndpi` which is LGPLv3 licensed. Applications using `ndpi-rs` must comply with LGPLv3 requirements when distributing binaries that include `libndpi`.
