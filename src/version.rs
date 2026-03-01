use crate::ffi;
use std::ffi::CStr;

#[derive(Debug, Clone)]
pub struct NdpiVersion {
    /// nDPI revision
    pub ndpi_revision: Option<String>,
    /// API version
    pub api_version: u16,
    /// libgcrypt version
    pub gcrypt_version: Option<String>,
}

impl NdpiVersion {
    pub fn new() -> Self {
        let mut ndpi_revision = None;
        let mut gcrypt_version = None;

        let ptr = unsafe { ffi::ndpi_revision() };
        if !ptr.is_null() {
            let c_str = unsafe { CStr::from_ptr(ptr) };
            ndpi_revision = Some(c_str.to_str().unwrap().to_string());
        }

        let ptr = unsafe { ffi::ndpi_get_gcrypt_version() };
        if !ptr.is_null() {
            let c_str = unsafe { CStr::from_ptr(ptr) };
            gcrypt_version = Some(c_str.to_str().unwrap().to_string());
        }

        let api_version = unsafe { ffi::ndpi_get_api_version() };

        NdpiVersion {
            ndpi_revision,
            api_version,
            gcrypt_version,
        }
    }
}
