pub mod detection;
pub mod error;
mod ffi;
pub mod flow;
pub mod types;
pub mod version;

pub use crate::detection::{NdpiDetection, NdpiGlobalCtx};
pub use crate::error::NdpiError;
pub use crate::ffi::ndpi_cfg_error;
pub use crate::ffi::ndpi_risk_enum;
pub use crate::flow::NdpiFlow;
pub use crate::version::NdpiVersion;

use std::ffi::CStr;

/// Converts risk enum to string representation.
pub fn risk_to_str(risk_enum: ndpi_risk_enum) -> Option<&'static CStr> {
    let risk_str = unsafe { ffi::ndpi_risk2str(risk_enum) };
    if risk_str.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(risk_str) })
    }
}

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
    use crate::{get_breed_by_name, get_breed_name, ndpi_risk_enum, risk_to_str};

    #[test]
    fn risk_to_str_test() {
        let risk = ndpi_risk_enum::NDPI_MALWARE_HOST_CONTACTED;
        let risk_str = risk_to_str(risk);
        assert!(risk_str.is_some());

        let invalid_risk = ndpi_risk_enum(101);
        let risk_str = risk_to_str(invalid_risk);
        assert!(risk_str.is_some());

        let risk_str = risk_str.unwrap();
        assert_eq!(risk_str, c"101");
    }

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
