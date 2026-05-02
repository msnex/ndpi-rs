use crate::error::NdpiError;
use crate::ffi::{self, ndpi_risk_enum};
use crate::types::{FlowDns, FlowHttp, FlowKerberos, FlowSsdp, FlowSsh, FlowTlsQuic};
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Wrapper for nDPI flow.
pub struct NdpiFlow {
    flow: *mut ffi::ndpi_flow_struct,
}

impl NdpiFlow {
    /// Creates a new nDPI flow structure.
    /// Allocates and zero-initializes the underlying C structure.
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

    /// Returns a mutable pointer to the underlying C flow structure.
    #[inline]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::ndpi_flow_struct {
        self.flow
    }

    /// Returns true if the protocol was guessed (not definitively detected).
    #[inline]
    pub fn protocol_was_guessed(&self) -> bool {
        let ret = unsafe { &*self.flow }.protocol_was_guessed();
        if ret == 1 { true } else { false }
    }

    /// Returns the number of packets processed for this flow.
    #[inline]
    pub fn num_processed_pkts(&self) -> u16 {
        unsafe { (&*self.flow).num_processed_pkts }
    }

    /// Returns true if the flow has any risk flags set.
    #[inline]
    pub fn has_risk(&self) -> bool {
        let risk = unsafe { (&*self.flow).risk };
        if risk != 0 { true } else { false }
    }

    /// Checks if a specific risk flag is set for this flow.
    #[inline]
    pub fn is_set_risk(&self, risk_enum: &ndpi_risk_enum) -> bool {
        let risk = unsafe { (&*self.flow).risk };
        if risk & (1u64 << risk_enum.0) != 0 {
            true
        } else {
            false
        }
    }

    /// Returns the raw risk bits as a 64-bit unsigned integer.
    /// Each bit represents a specific risk flag defined in ndpi_risk_enum.
    #[inline]
    pub fn get_risk_bits(&self) -> u64 {
        unsafe { (&*self.flow).risk }
    }

    /// Returns a vector of risk description strings for all set risk flags.
    #[inline]
    pub fn get_risk_str_vec(&self) -> Vec<&CStr> {
        let max_risks = ndpi_risk_enum::NDPI_MAX_RISK.0;
        let mut risk_strs = Vec::new();

        for risk in 0..max_risks {
            let risk_enum = ndpi_risk_enum(risk);
            if self.is_set_risk(&risk_enum) {
                if let Some(risk_str) = crate::risk::risk_to_str(risk_enum) {
                    risk_strs.push(risk_str);
                }
            }
        }
        risk_strs
    }

    /// Returns a vector of risk enum values for all set risk flags.
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

    #[inline]
    pub fn get_host_server_name<'a>(&self) -> Option<&'a CStr> {
        unsafe {
            if (&*self.flow).host_server_name[0] != 0 {
                Some(CStr::from_ptr((&*self.flow).host_server_name.as_ptr()))
            } else {
                None
            }
        }
    }

    /// Extracts DNS metadata from the flow's protos union.
    ///
    /// Returns DNS query/response fields populated by the nDPI DNS dissector.
    /// Response IP addresses are converted to `std::net::IpAddr`.
    /// The IATA code and PTR domain name are returned as owned `String`s.
    #[inline]
    pub fn get_dns<'a>(&self) -> FlowDns<'a> {
        let dns = unsafe { (&*self.flow).protos.dns.as_ref() };

        let mut rsp_addr: [Option<IpAddr>; 4] = [None, None, None, None];
        for i in 0..dns.num_rsp_addr.min(4) as usize {
            rsp_addr[i] = if dns.is_rsp_addr_ipv6[i] != 0 {
                let in6 = unsafe { dns.rsp_addr[i].ipv6.as_ref() };
                let bytes = unsafe { *in6.u6_addr.u6_addr8.as_ref() };
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            } else {
                let ip = unsafe { *dns.rsp_addr[i].ipv4.as_ref() };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(ip))))
            };
        }

        let iata_code = if dns.geolocation_iata_code[0] != 0 {
            Some(unsafe { CStr::from_ptr(dns.geolocation_iata_code.as_ptr()) })
        } else {
            None
        };

        let ptr_domain_name = if dns.ptr_domain_name[0] != 0 {
            Some(unsafe { CStr::from_ptr(dns.ptr_domain_name.as_ptr()) })
        } else {
            None
        };

        FlowDns {
            num_queries: dns.num_queries,
            num_answers: dns.num_answers,
            reply_code: dns.reply_code,
            num_rsp_addr: dns.num_rsp_addr,
            is_query: dns.is_query(),
            transaction_id: dns.transaction_id,
            query_name: self.get_host_server_name(),
            query_type: dns.query_type,
            query_class: dns.query_class,
            rsp_type: dns.rsp_type,
            edns0_udp_payload_size: dns.edns0_udp_payload_size,
            rsp_addr,
            rsp_addr_ttl: dns.rsp_addr_ttl,
            iata_code,
            ptr_domain_name,
        }
    }

    #[inline]
    pub fn get_http<'a>(&self) -> FlowHttp<'a> {
        // request

        let url = unsafe {
            if !(&*self.flow).http.url.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.url))
            } else {
                None
            }
        };

        let host = unsafe {
            if !(&*self.flow).http.host.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.host))
            } else {
                None
            }
        };

        let req_content_type = unsafe {
            if !(&*self.flow).http.request_content_type.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.request_content_type))
            } else {
                None
            }
        };

        let user_agent = unsafe {
            if !(&*self.flow).http.user_agent.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.user_agent))
            } else {
                None
            }
        };

        let referer = unsafe {
            if !(&*self.flow).http.referer.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.referer))
            } else {
                None
            }
        };

        let xxf = unsafe {
            if !(&*self.flow).http.nat_ip.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.nat_ip))
            } else {
                None
            }
        };

        let server = unsafe {
            if !(&*self.flow).http.server.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.server))
            } else {
                None
            }
        };

        let resp_content_type = unsafe {
            if !(&*self.flow).http.content_type.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.content_type))
            } else {
                None
            }
        };

        let filename = unsafe {
            if !(&*self.flow).http.filename.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.filename))
            } else {
                None
            }
        };

        let username = unsafe {
            if !(&*self.flow).http.username.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.username))
            } else {
                None
            }
        };

        let password = unsafe {
            if !(&*self.flow).http.password.is_null() {
                Some(CStr::from_ptr((&*self.flow).http.password))
            } else {
                None
            }
        };

        unsafe {
            FlowHttp {
                method: (&*self.flow).http.method.0 as u8,
                version: (&*self.flow).http.request_version,
                url,
                host,
                req_content_type,
                user_agent,
                referer,
                status_code: (&*self.flow).http.response_status_code,
                server,
                xxf,
                resp_content_type,
                filename,
                username,
                password,
            }
        }
    }

    #[inline]
    pub fn get_ssh<'a>(&self) -> FlowSsh<'a> {
        let ssh = unsafe { (&*self.flow).protos.ssh.as_ref() };

        let client_signature = if ssh.client_signature[0] != 0 {
            Some(unsafe { CStr::from_ptr(ssh.client_signature.as_ptr()) })
        } else {
            None
        };

        let server_signature = if ssh.server_signature[0] != 0 {
            Some(unsafe { CStr::from_ptr(ssh.server_signature.as_ptr()) })
        } else {
            None
        };

        let hassh_client = if ssh.hassh_client[0] != 0 {
            Some(unsafe { CStr::from_ptr(ssh.hassh_client.as_ptr()) })
        } else {
            None
        };

        let hassh_server = if ssh.hassh_server[0] != 0 {
            Some(unsafe { CStr::from_ptr(ssh.hassh_server.as_ptr()) })
        } else {
            None
        };

        FlowSsh {
            client_signature,
            server_signature,
            hassh_client,
            hassh_server,
        }
    }

    #[inline]
    pub fn get_kerberos<'a>(&self) -> FlowKerberos<'a> {
        let krb = unsafe { (&*self.flow).protos.kerberos.as_ref() };

        let hostname = if krb.hostname[0] != 0 {
            Some(unsafe { CStr::from_ptr(krb.hostname.as_ptr()) })
        } else {
            None
        };

        let domain = if krb.domain[0] != 0 {
            Some(unsafe { CStr::from_ptr(krb.domain.as_ptr()) })
        } else {
            None
        };

        let username = if krb.username[0] != 0 {
            Some(unsafe { CStr::from_ptr(krb.username.as_ptr()) })
        } else {
            None
        };

        FlowKerberos {
            hostname,
            domain,
            username,
        }
    }

    #[inline]
    pub fn get_tls_quic<'a>(&self) -> FlowTlsQuic<'a> {
        let tls_quic = unsafe { (&*self.flow).protos.tls_quic.as_ref() };

        let server_names = if !tls_quic.server_names.is_null() {
            Some(unsafe {
                core::slice::from_raw_parts(
                    tls_quic.server_names,
                    tls_quic.server_names_len as usize,
                )
            })
        } else {
            None
        };

        let issuer = if !tls_quic.issuerDN.is_null() {
            Some(unsafe { CStr::from_ptr(tls_quic.issuerDN) })
        } else {
            None
        };

        let subject = if !tls_quic.subjectDN.is_null() {
            Some(unsafe { CStr::from_ptr(tls_quic.subjectDN) })
        } else {
            None
        };

        let ja3_server = if tls_quic.ja3_server[0] != 0 {
            Some(unsafe { CStr::from_ptr(tls_quic.ja3_server.as_ptr()) })
        } else {
            None
        };

        FlowTlsQuic {
            sni: self.get_host_server_name(),
            server_names,
            issuer,
            subject,
            ja3_server,
            ssl_version: tls_quic.ssl_version,
            quic_version: tls_quic.quic_version,
            quic_idle_timeout_sec: tls_quic.quic_idle_timeout_sec,
        }
    }

    #[inline]
    pub fn get_flow_ssdp<'a>(&self) -> FlowSsdp<'a> {
        let ssdp = unsafe { (&*self.flow).protos.ssdp.as_ref() };

        let method = if !ssdp.method.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.method) })
        } else {
            None
        };

        let usn = if !ssdp.usn.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.usn) })
        } else {
            None
        };

        let location = if !ssdp.location.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.location) })
        } else {
            None
        };

        let nt = if !ssdp.nt.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.nt) })
        } else {
            None
        };

        let nts = if !ssdp.nts.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.nts) })
        } else {
            None
        };

        let server = if !ssdp.server.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.server) })
        } else {
            None
        };

        let man = if !ssdp.man.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.man) })
        } else {
            None
        };

        let st = if !ssdp.st.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.st) })
        } else {
            None
        };

        let user_agent = if !ssdp.user_agent.is_null() {
            Some(unsafe { CStr::from_ptr(ssdp.user_agent) })
        } else {
            None
        };

        FlowSsdp {
            method,
            usn,
            location,
            nt,
            nts,
            server,
            man,
            st,
            user_agent,
        }
    }
}

impl Drop for NdpiFlow {
    /// Cleans up the allocated nDPI flow structure.
    fn drop(&mut self) {
        if !self.flow.is_null() {
            unsafe {
                ffi::ndpi_flow_free(self.flow.cast());
            }
        }
    }
}
