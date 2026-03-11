use crate::ffi;

#[derive(Debug, Default)]
pub struct NdpiProtocol {
    pub master_protocol: u16,
    pub app_protocol: u16,
    pub breed: u32,
    pub category: u32,
}

impl NdpiProtocol {
    #[inline]
    pub fn protocol_detected(&self) -> bool {
        let unknown_proto = ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_UNKNOWN.0 as u16;
        if self.master_protocol != unknown_proto
            || self.app_protocol != unknown_proto
            || self.category != ffi::ndpi_protocol_category_t::NDPI_PROTOCOL_CATEGORY_UNSPECIFIED.0
        {
            true
        } else {
            false
        }
    }
}
