# ndpi-rs
Safe Rust Bindings for [nDPI](https://github.com/ntop/nDPI)

## Dependencies
- rust 1.92.0
- pkg-config
- libndpi >= 5.0.0

## Build
### libndpi
Reference: https://github.com/ntop/nDPI/blob/dev/README.md

### ndpi-rs
This crate use `pkg-config` to locate `libndpi` library.
