use crate::error::NdpiError;
use crate::ffi::{self, ndpi_risk_enum};
use std::ffi::CStr;

pub const NDPI_IN_PKT_DIR_UNKNOWN: u8 = 0;
pub const NDPI_IN_PKT_DIR_C_TO_S: u8 = 1;
pub const NDPI_IN_PKT_DIR_S_TO_C: u8 = 2;
pub const NDPI_FLOW_BEGINNING_UNKNOWN: u8 = 0;
pub const NDPI_FLOW_BEGINNING_SEEN: u8 = 1;
pub const NDPI_FLOW_BEGINNING_NOT_SEEN: u8 = 2;

pub struct NdpiFlowInputInfo {
    input_info: ffi::ndpi_flow_input_info,
}

impl NdpiFlowInputInfo {
    #[inline]
    pub fn new(in_pkt_dir: u8, seen_flow_beginning: u8) -> Self {
        Self {
            input_info: ffi::ndpi_flow_input_info {
                in_pkt_dir,
                seen_flow_beginning,
            },
        }
    }

    #[inline]
    pub(crate) fn as_ptr(&mut self) -> *mut ffi::ndpi_flow_input_info {
        &mut self.input_info
    }
}

pub struct NdpiFlow {
    flow: *mut ffi::ndpi_flow_struct,
}

impl NdpiFlow {
    #[inline]
    pub fn new() -> Result<Self, NdpiError> {
        let flow_size = unsafe { ffi::ndpi_detection_get_sizeof_ndpi_flow_struct() as usize };
        let flow = unsafe { ffi::ndpi_flow_malloc(flow_size) };
        if flow.is_null() {
            return Err(NdpiError::InitNdpiFlow);
        }

        unsafe {
            std::ptr::write_bytes(flow, 0, flow_size);
        }

        Ok(Self { flow: flow.cast() })
    }

    #[inline]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::ndpi_flow_struct {
        self.flow
    }

    #[inline]
    pub fn protocol_was_guessed(&self) -> bool {
        let ret = unsafe { &*self.flow }.protocol_was_guessed();
        if ret == 1 { true } else { false }
    }

    #[inline]
    pub fn num_processed_pkts(&self) -> u16 {
        unsafe { (&*self.flow).num_processed_pkts }
    }

    #[inline]
    pub fn has_risk(&self) -> bool {
        let risk = unsafe { (&*self.flow).risk };
        if risk != 0 { true } else { false }
    }

    #[inline]
    pub fn is_set_risk(&self, risk_enum: &ndpi_risk_enum) -> bool {
        let risk = unsafe { (&*self.flow).risk };
        if risk & risk_enum.0 as u64 != 0 {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn get_risk_str_vec(&self) -> Vec<&CStr> {
        let max_risks = ndpi_risk_enum::NDPI_MAX_RISK.0;
        let mut risk_strs = Vec::new();

        for risk in 0..max_risks {
            let risk_enum = ndpi_risk_enum(risk);
            if self.is_set_risk(&risk_enum) {
                if let Some(risk_str) = crate::risk_to_str(risk_enum) {
                    risk_strs.push(risk_str);
                }
            }
        }
        risk_strs
    }

    #[inline]
    pub fn get_risk_enum_vec(&self) -> Vec<ndpi_risk_enum> {
        let max_risks = ndpi_risk_enum::NDPI_MAX_RISK.0;
        let mut risk_enums = Vec::new();

        for risk in 0..max_risks {
            let risk_enum = ndpi_risk_enum(risk);
            if self.is_set_risk(&risk_enum) {
                risk_enums.push(risk_enum);
            }
        }
        risk_enums
    }
}

impl Drop for NdpiFlow {
    fn drop(&mut self) {
        if !self.flow.is_null() {
            unsafe {
                ffi::ndpi_flow_free(self.flow.cast());
            }
        }
    }
}
