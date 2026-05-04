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
    fn is_app_proto(&self, app_proto: u32) -> bool {
        if app_proto > u16::MAX as u32 {
            return false;
        }

        let protocol = app_proto as u16;
        if self.master_protocol == protocol || self.app_protocol == protocol {
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn is_http(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_HTTP.0)
    }

    #[inline]
    pub fn is_dns(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_DNS.0)
    }

    #[inline]
    pub fn is_mdns(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_MDNS.0)
    }

    #[inline]
    pub fn is_llmnr(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_LLMNR.0)
    }

    #[inline]
    pub fn is_ssh(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_SSH.0)
    }

    #[inline]
    pub fn is_kerberos(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_KERBEROS.0)
    }

    #[inline]
    pub fn is_tls(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_TLS.0)
    }

    #[inline]
    pub fn is_dtls(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_DTLS.0)
    }

    #[inline]
    pub fn is_quic(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_QUIC.0)
    }

    #[inline]
    pub fn is_ssdp(&self) -> bool {
        self.is_app_proto(ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_SSDP.0)
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

#[derive(Debug, Default, Clone)]
pub struct FlowSsh<'a> {
    pub client_signature: Option<&'a CStr>,
    pub server_signature: Option<&'a CStr>,
    pub hassh_client: Option<&'a CStr>,
    pub hassh_server: Option<&'a CStr>,
}

#[derive(Debug, Default, Clone)]
pub struct FlowKerberos<'a> {
    pub hostname: Option<&'a CStr>,
    pub domain: Option<&'a CStr>,
    pub username: Option<&'a CStr>,
}

#[derive(Debug, Default, Clone)]
pub struct FlowTlsQuic<'a> {
    pub sni: Option<&'a CStr>,
    pub server_names: Option<&'a [i8]>,
    pub issuer: Option<&'a CStr>,
    pub subject: Option<&'a CStr>,
    pub ja3_server: Option<&'a CStr>,
    pub ssl_version: u16,
    pub quic_version: u32,
    pub quic_idle_timeout_sec: u32,
}

#[derive(Debug, Default, Clone)]
pub struct FlowSsdp<'a> {
    pub method: Option<&'a CStr>,
    pub usn: Option<&'a CStr>,
    pub location: Option<&'a CStr>,
    pub nt: Option<&'a CStr>,
    pub nts: Option<&'a CStr>,
    pub server: Option<&'a CStr>,
    pub man: Option<&'a CStr>,
    pub st: Option<&'a CStr>,
    pub user_agent: Option<&'a CStr>,
}
