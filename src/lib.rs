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

fn risk_to_str(risk_enum: ndpi_risk_enum) -> Option<&'static CStr> {
    let risk_str = unsafe { ffi::ndpi_risk2str(risk_enum) };
    if risk_str.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(risk_str) })
    }
}

#[cfg(test)]
mod tests {
    use crate::{ndpi_risk_enum, risk_to_str};

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
}
