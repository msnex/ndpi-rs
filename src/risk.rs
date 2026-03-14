use crate::ffi::{self, ndpi_risk_enum};
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

#[inline]
fn is_set_risk(risk_bits: u64, risk_enum: &ndpi_risk_enum) -> bool {
    if risk_bits & (1u64 << risk_enum.0) != 0 {
        true
    } else {
        false
    }
}

/// Converts risk bits to a vector of risk description strings.
pub fn risk_bits_to_str_vec(risk_bits: u64) -> Option<Vec<&'static CStr>> {
    if risk_bits == 0 {
        return None;
    }

    let max_risks = ndpi_risk_enum::NDPI_MAX_RISK.0;
    let mut risk_strs = Vec::new();

    for risk in 0..max_risks {
        let risk_enum = ndpi_risk_enum(risk);
        if is_set_risk(risk_bits, &risk_enum) {
            if let Some(risk_str) = risk_to_str(risk_enum) {
                risk_strs.push(risk_str);
            }
        }
    }
    Some(risk_strs)
}

#[cfg(test)]
mod tests {
    use super::{ndpi_risk_enum, risk_bits_to_str_vec, risk_to_str};

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
    fn risk_bits_to_str_vec_test() {
        let risk_bits = (1u64 << ndpi_risk_enum::NDPI_MALFORMED_PACKET.0)
            | (1u64 << ndpi_risk_enum::NDPI_MALWARE_HOST_CONTACTED.0);
        let str_vec = risk_bits_to_str_vec(risk_bits);
        assert!(str_vec.is_some());
        assert_eq!(str_vec.unwrap().len(), 2);
    }
}
