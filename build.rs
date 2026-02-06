use std::error::Error;

const NDPI_AT_LEAST_VERSION: &'static str = "5.0.0";

#[derive(PartialEq, PartialOrd)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    const AT_LEAST_VERSION: Self = Self {
        major: 5,
        minor: 0,
        patch: 0,
    };
}

fn parse_version(version: &str) -> Result<Version, Box<dyn Error>> {
    let splits: Vec<&str> = version.split('.').collect();
    if splits.len() != 3 {
        return Err(format!("Invalid libndpi version: {}", version).into());
    }

    Ok(Version {
        major: splits[0].parse::<u32>()?,
        minor: splits[1].parse::<u32>()?,
        patch: splits[2].parse::<u32>()?,
    })
}

fn main() {
    let mut config = pkg_config::Config::new();
    let lib = config
        .atleast_version(&NDPI_AT_LEAST_VERSION)
        .statik(true)
        .probe("libndpi")
        .unwrap();

    let version = parse_version(&lib.version).unwrap();
    assert!(
        version >= Version::AT_LEAST_VERSION,
        "required libndpi version >= 5.0.0"
    );

    println!(
        "cargo:rustc-check-cfg=cfg(libndpi_{}_{}_{})",
        version.major, version.minor, version.patch
    );
    println!(
        "cargo:rustc-cfg=libndpi_{}_{}_{}",
        version.major, version.minor, version.patch
    );
}
