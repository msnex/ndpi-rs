use crate::error::NdpiError;
use crate::ffi;
use libc::c_void;

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
    pub fn new() -> Result<Self, NdpiError> {
        let flow_size = unsafe { ffi::ndpi_detection_get_sizeof_ndpi_flow_struct() as usize };
        let flow = unsafe { ffi::ndpi_flow_malloc(flow_size) };
        if flow.is_null() {
            return Err(NdpiError::InitNdpiFlow);
        }

        unsafe {
            std::ptr::write_bytes(flow, 0, flow_size);
        }

        Ok(Self {
            flow: flow as *mut ffi::ndpi_flow_struct,
        })
    }

    pub fn protocol_was_guessed(&self) -> bool {
        let ret = unsafe { &*self.flow }.protocol_was_guessed();
        if ret == 1 { true } else { false }
    }

    pub fn num_processed_pkts(&self) -> u16 {
        unsafe { (&*self.flow).num_processed_pkts }
    }

    #[inline]
    pub(crate) fn as_ptr(&mut self) -> *mut ffi::ndpi_flow_struct {
        self.flow
    }
}

impl Drop for NdpiFlow {
    fn drop(&mut self) {
        if !self.flow.is_null() {
            unsafe {
                ffi::ndpi_flow_free(self.flow as *mut c_void);
            }
        }
    }
}
