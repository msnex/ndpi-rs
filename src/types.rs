use crate::ffi;
use std::ffi::CStr;
use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct NdpiProtocol {
    pub master_protocol: u16,
    pub app_protocol: u16,
    pub breed: u32,
    pub category: u32,
    pub state: u32,
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

    #[inline]
    pub fn classified(&self) -> bool {
        self.state == ffi::ndpi_classification_state::NDPI_STATE_CLASSIFIED.0
    }

    #[inline]
    pub fn is_http(&self) -> bool {
        let http_proto = ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_HTTP.0 as u16;
        if self.master_protocol == http_proto || self.app_protocol == http_proto {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_dns(&self) -> bool {
        let dns_proto = ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_DNS.0 as u16;
        if self.master_protocol == dns_proto || self.app_protocol == dns_proto {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct FlowHttp<'a> {
    // request
    pub method: u8,
    pub version: u8,
    pub url: Option<&'a CStr>,
    pub host: Option<&'a CStr>,
    pub req_content_type: Option<&'a CStr>,
    pub user_agent: Option<&'a CStr>,
    pub referer: Option<&'a CStr>,
    // response
    pub status_code: u16,
    pub server: Option<&'a CStr>,
    pub xxf: Option<&'a CStr>,
    pub resp_content_type: Option<&'a CStr>,
    // both
    pub filename: Option<&'a CStr>,
    pub username: Option<&'a CStr>,
    pub password: Option<&'a CStr>,
}

/// DNS metadata extracted from a flow.
///
/// Populated when the flow's protocol is detected as DNS.
/// Contains query/response counts, transaction IDs, query types,
/// response IP addresses with TTLs, and PTR domain names.
#[derive(Debug, Default, Clone)]
pub struct FlowDns<'a> {
    pub num_queries: u8,
    pub num_answers: u8,
    pub reply_code: u8,
    pub num_rsp_addr: u8,
    pub is_query: u8,
    pub transaction_id: u16,
    pub query_name: Option<&'a CStr>,
    pub query_type: u16,
    pub query_class: u16,
    pub rsp_type: u16,
    pub edns0_udp_payload_size: u16,
    pub rsp_addr: [Option<IpAddr>; 4],
    pub rsp_addr_ttl: [u32; 4],
    pub iata_code: Option<&'a CStr>,
    pub ptr_domain_name: Option<&'a CStr>,
}
