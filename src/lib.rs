pub mod detection;
pub mod error;
pub mod ffi;
pub mod flow;
pub mod risk;
pub mod types;
pub mod version;

pub use crate::detection::{NdpiDetection, NdpiGlobalCtx};
pub use crate::error::NdpiError;
pub use crate::flow::NdpiFlow;
pub use crate::version::NdpiVersion;

use std::ffi::CStr;

/// Gets protocol breed name by breed ID.
pub fn get_breed_name(breed: u32) -> Option<&'static CStr> {
    let breed_id = ffi::ndpi_protocol_breed_t(breed);
    let breed_name = unsafe { ffi::ndpi_get_proto_breed_name(breed_id) };
    if breed_name.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(breed_name) })
    }
}

/// Gets breed ID by breed name.
pub fn get_breed_by_name(name: &CStr) -> u32 {
    let breed_id = unsafe { ffi::ndpi_get_breed_by_name(name.as_ptr()) };
    breed_id.0
}

// Get http method string
pub fn get_http_method_name(method: u8) -> Option<&'static CStr> {
    let method_ptr = unsafe { ffi::ndpi_http_method2str(ffi::ndpi_http_method(method as u32)) };
    if method_ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(method_ptr) })
    }
}

// Get TLS version string
pub fn get_tls_version_str(version: u16) -> Option<&'static str> {
    match version {
        0x0300 => Some("SSL v3"),
        0x0301 => Some("TLS v1"),
        0x0302 => Some("TLS v1.1"),
        0x0303 => Some("TLS v1.2"),
        0x0304 => Some("TLS v1.3"),
        0xFB1A => Some("TLS v1.3 (Fizz)"),
        0xFEFF => Some("DTLS v1.0"),
        0xFEFD => Some("DTLS v1.2"),
        0xFEFC => Some("DTLS v1.3"),
        0x0A0A | 0x1A1A | 0x2A2A | 0x3A3A | 0x4A4A | 0x5A5A | 0x6A6A | 0x7A7A | 0x8A8A | 0x9A9A
        | 0xAAAA | 0xBABA | 0xCACA | 0xDADA | 0xEAEA | 0xFAFA => Some("GREASE"),
        v if (0x7F00..=0x7FFF).contains(&v) => Some("TLS v1.3 (draft)"),
        _ => None,
    }
}

// Get QUIC version string
pub fn get_quic_version_str(version: u32) -> Option<&'static str> {
    match version {
        0x6b3343cf => Some("V-2"),
        0x00000001 => Some("V-1"),
        0x51303234 => Some("Q024"),
        0x51303235 => Some("Q025"),
        0x51303330 => Some("Q030"),
        0x51303333 => Some("Q033"),
        0x51303334 => Some("Q034"),
        0x51303335 => Some("Q035"),
        0x51303337 => Some("Q037"),
        0x51303339 => Some("Q039"),
        0x51303433 => Some("Q043"),
        0x51303436 => Some("Q046"),
        0x51303530 => Some("Q050"),
        0x54303530 => Some("T050"),
        0x54303531 => Some("T051"),
        0xfaceb001 => Some("MVFST-22"),
        0xfaceb002 => Some("MVFST-27"),
        0xfaceb00e => Some("MVFST-EXP"),
        v if (v & 0x0F0F0F0F) == 0x0a0a0a0a => Some("Ver-Negotiation"),
        _ => None,
    }
}

// Get DNS error code string
pub fn get_dns_error_code_str(error_code: u8) -> Option<&'static str> {
    match error_code {
        1 => Some("FORMERR"),
        2 => Some("SERVFAIL"),
        3 => Some("NXDOMAIN"),
        4 => Some("NOTIMP"),
        5 => Some("REFUSED"),
        6 => Some("YXDOMAIN"),
        7 => Some("XRRSET"),
        8 => Some("NOTAUTH"),
        9 => Some("NOTZONE"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{get_breed_by_name, get_breed_name};

    #[test]
    fn get_breed_name_test() {
        let name = get_breed_name(101);
        assert!(name.is_some());
        assert_eq!(name.unwrap(), c"???");

        let name = get_breed_name(1);
        assert!(name.is_some());
        assert_eq!(name.unwrap(), c"Safe");
    }

    #[test]
    fn get_breed_by_name_test() {
        let breed_id = get_breed_by_name(&c"Unsafe");
        assert_eq!(breed_id, 4);

        let breed_id = get_breed_by_name(&c"Unknown");
        assert_eq!(breed_id, 0);
    }
}
