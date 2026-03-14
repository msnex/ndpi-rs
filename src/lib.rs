pub mod detection;
pub mod error;
mod ffi;
pub mod flow;
pub mod risk;
pub mod types;
pub mod version;

pub use crate::detection::{NdpiDetection, NdpiGlobalCtx};
pub use crate::error::NdpiError;
pub use crate::ffi::ndpi_cfg_error;
pub use crate::ffi::ndpi_risk_enum;
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
