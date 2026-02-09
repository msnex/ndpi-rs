use std::{env, error::Error, path::PathBuf};

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

fn bindgen_libndpi() {
    let target = env::var("TARGET").unwrap();

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg(format!("--target={}", target))
        .layout_tests(false)
        .derive_default(true)
        .derive_copy(false)
        .fit_macro_constants(true)
        .generate_comments(true)
        .generate_inline_functions(true)
        .generate_cstr(true)
        .ctypes_prefix("libc")
        .bitfield_enum(".*")
        .opaque_type("ndpi_detection_module_struct")
        .opaque_type("ndpi_global_context")
        .wrap_unsafe_ops(true)
        .rust_edition(bindgen::RustEdition::Edition2024);

    if target.contains("openbsd") {
        builder = builder.clang_arg("-D__OpenBSD__");
    } else if target.contains("freebsd") {
        builder = builder.clang_arg("-D__FreeBSD__");
    } else if target.contains("linux") {
        builder = builder.clang_arg("-D__linux__");
    } else if target.contains("windows") {
        builder = builder.clang_arg("-DWIN32");
    }

    let bindings = builder
        .generate()
        .expect("unable to generate libndpi bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write libndpi bindings");
}

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let mut config = pkg_config::Config::new();
    let lib = config
        .atleast_version(&NDPI_AT_LEAST_VERSION)
        .probe("libndpi")
        .unwrap();

    let version = parse_version(&lib.version).unwrap();
    assert!(
        version >= Version::AT_LEAST_VERSION,
        "required libndpi version >= 5.0.0"
    );

    bindgen_libndpi();

    println!(
        "cargo:rustc-check-cfg=cfg(libndpi_{}_{}_{})",
        version.major, version.minor, version.patch
    );
    println!(
        "cargo:rustc-cfg=libndpi_{}_{}_{}",
        version.major, version.minor, version.patch
    );
}
