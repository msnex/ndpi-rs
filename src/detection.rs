use crate::error::NdpiError;
use crate::ffi;
use crate::flow::{NdpiFlow, NdpiFlowInputInfo};
use crate::types::NdpiMasterAppProtocol;
use libc::c_int;
use std::ffi::CStr;

/// Wrapper for nDPI global context.
///
/// Manages shared resources and initialization for detection modules.
pub struct NdpiGlobalCtx {
    g_ctx: *mut ffi::ndpi_global_context,
}

impl NdpiGlobalCtx {
    /// Creates a new global context.
    ///
    /// Initializes shared resources required for detection modules.
    ///
    /// # Returns
    ///
    /// - `Ok(NdpiGlobalCtx)` - Successfully initialized
    /// - `Err(NdpiError::InitNdpiGlobalCtx)` - Initialization failed
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::NdpiGlobalCtx;
    ///
    /// let global_ctx = NdpiGlobalCtx::new().unwrap();
    /// ```
    #[inline]
    pub fn new() -> Result<Self, NdpiError> {
        let ctx = unsafe { ffi::ndpi_global_init() };
        if ctx.is_null() {
            return Err(NdpiError::InitNdpiGlobalCtx);
        }
        Ok(Self { g_ctx: ctx })
    }
}

impl Drop for NdpiGlobalCtx {
    /// Cleans up global context resources.
    ///
    /// Automatically called when `NdpiGlobalCtx` goes out of scope.
    fn drop(&mut self) {
        if !self.g_ctx.is_null() {
            unsafe {
                ffi::ndpi_global_deinit(self.g_ctx);
            }
        }
    }
}

/// Wrapper for nDPI detection module.
///
/// Manages protocol detection and analysis of network traffic.
pub struct NdpiDetection {
    ndpi_struct: *mut ffi::ndpi_detection_module_struct,
    detected_l7_proto: ffi::ndpi_proto,
    guessed_l7_proto: ffi::ndpi_proto,
}

impl NdpiDetection {
    /// Creates a new detection module.
    ///
    /// Optionally uses a shared global context for resource management.
    ///
    /// # Arguments
    ///
    /// * `g_ctx` - Optional global context reference. If `None`, uses internal resources.
    ///
    /// # Returns
    ///
    /// - `Ok(NdpiDetection)` - Successfully initialized
    /// - `Err(NdpiError::InitNdpiDetectionModule)` - Initialization failed
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiGlobalCtx, NdpiDetection};
    ///
    /// // With global context
    /// let global_ctx = NdpiGlobalCtx::new().unwrap();
    /// let detection = NdpiDetection::new(Some(&global_ctx)).unwrap();
    ///
    /// // Without global context
    /// let detection = NdpiDetection::new(None).unwrap();
    /// ```
    pub fn new(g_ctx: Option<&NdpiGlobalCtx>) -> Result<Self, NdpiError> {
        let ndpi_struct;
        if let Some(ctx) = g_ctx {
            ndpi_struct = unsafe { ffi::ndpi_init_detection_module(ctx.g_ctx) }
        } else {
            ndpi_struct = unsafe { ffi::ndpi_init_detection_module(std::ptr::null_mut()) }
        }

        if ndpi_struct.is_null() {
            return Err(NdpiError::InitNdpiDetectionModule);
        }

        Ok(Self {
            ndpi_struct,
            detected_l7_proto: ffi::ndpi_proto::default(),
            guessed_l7_proto: ffi::ndpi_proto::default(),
        })
    }

    /// Finalizes detection module initialization.
    ///
    /// Must be called after configuration and before packet processing.
    /// Configuration changes may not be allowed after finalization.
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully finalized
    /// - `Err(NdpiError::FinalizeNdpiDetectionModule)` - Finalization failed
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    /// ```
    pub fn finalize(&mut self) -> Result<(), NdpiError> {
        let ret = unsafe { ffi::ndpi_finalize_initialization(self.ndpi_struct) };
        if ret == 0 {
            Ok(())
        } else {
            Err(NdpiError::FinalizeNdpiDetectionModule)
        }
    }

    /// Sets a string configuration parameter.
    ///
    /// Must be called before `finalize()`. Configuration can be global or protocol-specific.
    ///
    /// # Arguments
    ///
    /// * `proto` - Optional protocol name (C string). `None` for global configuration.
    /// * `param` - Parameter name (C string).
    /// * `value` - Parameter value (C string).
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully configured
    /// - `Err(ndpi_cfg_error)` - Configuration failed
    ///
    /// # Example
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    ///
    /// // Configure before finalization
    /// let param = CStr::from_bytes_with_nul(b"packets_limit_per_flow\0").unwrap();
    /// let value = CStr::from_bytes_with_nul(b"64\0").unwrap();
    /// let _ = detection.set_config(None, param, value);
    ///
    /// detection.finalize().unwrap();
    /// ```
    pub fn set_config(
        &mut self,
        proto: Option<&CStr>,
        param: &CStr,
        value: &CStr,
    ) -> Result<(), ffi::ndpi_cfg_error> {
        let protocol = if let Some(protocol) = proto {
            protocol.as_ptr()
        } else {
            std::ptr::null()
        };

        let ret = unsafe {
            ffi::ndpi_set_config(self.ndpi_struct, protocol, param.as_ptr(), value.as_ptr())
        };

        if ret != ffi::ndpi_cfg_error::NDPI_CFG_OK {
            Err(ret)
        } else {
            Ok(())
        }
    }

    /// Sets a 64-bit unsigned integer configuration parameter.
    ///
    /// Must be called before `finalize()`. Configuration can be global or protocol-specific.
    ///
    /// # Arguments
    ///
    /// * `proto` - Optional protocol name (C string). `None` for global configuration.
    /// * `param` - Parameter name (C string).
    /// * `value` - Parameter value (u64).
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Successfully configured
    /// - `Err(ndpi_cfg_error)` - Configuration failed
    ///
    /// # Example
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    ///
    /// // Configure before finalization
    /// let param = CStr::from_bytes_with_nul(b"packets_limit_per_flow\0").unwrap();
    /// let _ = detection.set_config_u64(None, param, 32);
    ///
    /// detection.finalize().unwrap();
    /// ```
    pub fn set_config_u64(
        &mut self,
        proto: Option<&CStr>,
        param: &CStr,
        value: u64,
    ) -> Result<(), ffi::ndpi_cfg_error> {
        let protocol = if let Some(protocol) = proto {
            protocol.as_ptr()
        } else {
            std::ptr::null()
        };

        let ret =
            unsafe { ffi::ndpi_set_config_u64(self.ndpi_struct, protocol, param.as_ptr(), value) };

        if ret != ffi::ndpi_cfg_error::NDPI_CFG_OK {
            Err(ret)
        } else {
            Ok(())
        }
    }

    /// Retrieves a configuration parameter value.
    ///
    /// Can be called before or after `finalize()`. Configuration can be global or protocol-specific.
    ///
    /// # Arguments
    ///
    /// * `proto` - Optional protocol name (C string). `None` for global configuration.
    /// * `param` - Parameter name (C string).
    ///
    /// # Returns
    ///
    /// - `Ok(String)` - Parameter value
    /// - `Err(ndpi_cfg_error::NDPI_CFG_NOT_FOUND)` - Parameter not found
    ///
    /// # Example
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    ///
    /// // Get configuration before finalization
    /// let param = CStr::from_bytes_with_nul(b"packets_limit_per_flow\0").unwrap();
    /// match detection.get_config(None, param) {
    ///     Ok(value) => println!("Parameter value: {}", value),
    ///     Err(e) => println!("Parameter not found: {:?}", e),
    /// }
    ///
    /// detection.finalize().unwrap();
    /// ```
    pub fn get_config(
        &self,
        proto: Option<&CStr>,
        param: &CStr,
    ) -> Result<String, ffi::ndpi_cfg_error> {
        let mut value = vec![0i8; 256];

        let protocol = if let Some(protocol) = proto {
            protocol.as_ptr()
        } else {
            std::ptr::null()
        };

        let res = unsafe {
            ffi::ndpi_get_config(
                self.ndpi_struct,
                protocol,
                param.as_ptr(),
                value.as_mut_ptr(),
                value.len() as c_int,
            )
        };

        if res.is_null() {
            return Err(ffi::ndpi_cfg_error::NDPI_CFG_NOT_FOUND);
        }

        let c_str = unsafe { CStr::from_ptr(value.as_ptr()) };
        let str = c_str.to_string_lossy().to_string();
        Ok(str)
    }

    /// Processes a packet for protocol detection.
    ///
    /// Main packet processing function. Analyzes packet to detect application layer protocol.
    /// Use `protocol_was_detected()` to check results after processing.
    ///
    /// # Arguments
    ///
    /// * `flow` - Network flow reference.
    /// * `flow_input_info` - Optional flow input information.
    /// * `packet` - Raw IP packet data.
    /// * `packet_len` - Packet length in bytes.
    /// * `packet_time_ms` - Packet timestamp in milliseconds.
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// let flow = NdpiFlow::new().unwrap();
    /// let packet_data = vec![0x45, 0x00, 0x00, 0x54]; // Example IP packet
    ///
    /// detection.process_packet(&flow, None, &packet_data, packet_data.len() as u16, 1234567890);
    ///
    /// if detection.protocol_was_detected() {
    ///     // Protocol was detected
    /// }
    /// ```
    pub fn process_packet(
        &mut self,
        flow: &mut NdpiFlow,
        flow_input_info: Option<&mut NdpiFlowInputInfo>,
        packet: &[u8],
        packet_len: u16,
        packet_time_ms: u64,
    ) {
        let input_info = if let Some(input_info) = flow_input_info {
            input_info.as_ptr()
        } else {
            std::ptr::null_mut()
        };

        self.detected_l7_proto = unsafe {
            ffi::ndpi_detection_process_packet(
                self.ndpi_struct,
                flow.as_ptr(),
                packet.as_ptr(),
                packet_len,
                packet_time_ms,
                input_info,
            )
        };
    }

    /// Checks if a protocol was detected.
    ///
    /// Returns `true` if master protocol, application protocol, or category was identified.
    ///
    /// # Returns
    ///
    /// - `true` - Protocol detected
    /// - `false` - No protocol detected
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// // Initially, no protocol is detected
    /// assert!(!detection.protocol_was_detected());
    ///
    /// // After processing packets, this may return true
    /// // detection.process_packet(...);
    /// // if detection.protocol_was_detected() {
    /// //     // Protocol was detected
    /// // }
    /// ```
    #[inline]
    pub fn protocol_was_detected(&self) -> bool {
        let unknown_proto = ffi::ndpi_protocol_id_t::NDPI_PROTOCOL_UNKNOWN.0 as u16;
        if self.detected_l7_proto.proto.master_protocol != unknown_proto
            || self.detected_l7_proto.proto.app_protocol != unknown_proto
            || self.detected_l7_proto.category
                != ffi::ndpi_protocol_category_t::NDPI_PROTOCOL_CATEGORY_UNSPECIFIED
        {
            true
        } else {
            false
        }
    }

    /// Gets detected master and application protocol.
    ///
    /// Returns protocol IDs from the last `process_packet` call.
    ///
    /// # Returns
    ///
    /// `NdpiMasterAppProtocol` with:
    /// - `master_protocol` - Master protocol ID (e.g., HTTP, TLS)
    /// - `app_protocol` - Application protocol ID (e.g., Facebook, YouTube)
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// let flow = NdpiFlow::new().unwrap();
    /// // Process a packet...
    ///
    /// let protocol = detection.get_master_app_protocol();
    /// println!("Master protocol: {}, App protocol: {}",
    ///          protocol.master_protocol, protocol.app_protocol);
    /// ```
    #[inline]
    pub fn get_master_app_protocol(&self) -> NdpiMasterAppProtocol {
        NdpiMasterAppProtocol {
            master_protocol: self.detected_l7_proto.proto.master_protocol,
            app_protocol: self.detected_l7_proto.proto.app_protocol,
        }
    }

    /// Gets detected protocol category.
    ///
    /// Returns category ID from the last `process_packet` call.
    /// Categories group protocols by function (e.g., Web, Streaming, SocialNetwork).
    ///
    /// # Returns
    ///
    /// Protocol category ID (`u32`).
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// let flow = NdpiFlow::new().unwrap();
    /// // Process a packet...
    ///
    /// let category_id = detection.get_protocol_category();
    /// let category_name = detection.get_protocol_category_name(category_id);
    /// println!("Protocol category: {}", category_name.to_str().unwrap());
    /// ```
    #[inline]
    pub fn get_protocol_category(&self) -> u32 {
        self.detected_l7_proto.category.0
    }

    /// Attempts protocol guessing when detection fails.
    ///
    /// Reduces NDPI_UNKNOWN_PROTOCOL detection. Use `get_guessed_*` methods to access results.
    /// Must be called before accessing guessed protocol information.
    ///
    /// # Arguments
    ///
    /// * `flow` - Flow reference for guessing.
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    /// let flow = NdpiFlow::new().unwrap();
    ///
    /// // Force early detection
    /// detection.giveup(&flow);
    ///
    /// // Get the guessed protocol (only meaningful after giveup())
    /// let guessed_proto = detection.get_guessed_master_app_protocol();
    /// println!("Guessed protocol: {}", detection.get_protocol_name(guessed_proto.master_protocol).to_str().unwrap());
    /// ```
    pub fn giveup(&mut self, flow: &mut NdpiFlow) {
        self.guessed_l7_proto =
            unsafe { ffi::ndpi_detection_giveup(self.ndpi_struct, flow.as_ptr()) }
    }

    /// Gets guessed master and application protocol.
    ///
    /// Returns protocol IDs from `giveup()` when regular detection failed.
    ///
    /// # Returns
    ///
    /// `NdpiMasterAppProtocol` with:
    /// - `master_protocol` - Guessed master protocol ID
    /// - `app_protocol` - Guessed application protocol ID
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// let flow = NdpiFlow::new().unwrap();
    /// // Process packets without successful detection...
    ///
    /// // Try to guess the protocol
    /// detection.giveup(&flow);
    ///
    /// let guessed_protocol = detection.get_guessed_master_app_protocol();
    /// println!("Guessed master protocol: {}, Guessed app protocol: {}",
    ///          guessed_protocol.master_protocol, guessed_protocol.app_protocol);
    /// ```
    #[inline]
    pub fn get_guessed_master_app_protocol(&self) -> NdpiMasterAppProtocol {
        NdpiMasterAppProtocol {
            master_protocol: self.guessed_l7_proto.proto.master_protocol,
            app_protocol: self.guessed_l7_proto.proto.app_protocol,
        }
    }

    /// Gets guessed protocol category.
    ///
    /// Returns category ID from `giveup()` when regular detection failed.
    ///
    /// # Returns
    ///
    /// Guessed protocol category ID (`u32`).
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::{NdpiDetection, NdpiFlow};
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    ///
    /// let flow = NdpiFlow::new().unwrap();
    /// // Process packets without successful detection...
    ///
    /// // Try to guess the protocol
    /// detection.giveup(&flow);
    ///
    /// let guessed_category_id = detection.get_guessed_protocol_category();
    /// let guessed_category_name = detection.get_protocol_category_name(guessed_category_id);
    /// println!("Guessed protocol category: {}", guessed_category_name.to_str().unwrap());
    /// ```
    #[inline]
    pub fn get_guessed_protocol_category(&self) -> u32 {
        self.guessed_l7_proto.category.0
    }

    /// Gets protocol name by ID.
    ///
    /// Returns "Unknown" if protocol ID is not recognized.
    ///
    /// # Arguments
    ///
    /// * `proto_id` - Protocol ID to look up.
    ///
    /// # Returns
    ///
    /// Protocol name as C string reference.
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    /// // process packet
    /// let protocol_name = detection.get_protocol_name(7);
    /// println!("Protocol name: {}", protocol_name.to_str().unwrap());
    /// ```
    pub fn get_protocol_name(&self, proto_id: u16) -> &CStr {
        let ptr = unsafe { ffi::ndpi_get_proto_name(self.ndpi_struct, proto_id) };
        if ptr.is_null() {
            return c"Unknown";
        }

        unsafe { CStr::from_ptr(ptr) }
    }

    /// Gets category name by ID.
    ///
    /// Returns "Unknown" if category ID is not recognized.
    ///
    /// # Arguments
    ///
    /// * `category_id` - Category ID to look up.
    ///
    /// # Returns
    ///
    /// Category name as C string reference.
    ///
    /// # Example
    ///
    /// ```
    /// use ndpi::NdpiDetection;
    ///
    /// let mut detection = NdpiDetection::new(None).unwrap();
    /// detection.finalize().unwrap();
    /// // process packet
    /// let category_name = detection.get_protocol_category_name(5); // Web category ID
    /// println!("Category name: {}", category_name.to_str().unwrap());
    /// ```
    pub fn get_protocol_category_name(&self, category_id: u32) -> &CStr {
        let category = ffi::ndpi_protocol_category_t(category_id);
        let ptr = unsafe { ffi::ndpi_category_get_name(self.ndpi_struct, category) };
        if ptr.is_null() {
            return c"Unknown";
        }

        unsafe { CStr::from_ptr(ptr) }
    }
}

impl Drop for NdpiDetection {
    /// Cleans up detection module resources.
    ///
    /// Automatically called when `NdpiDetection` goes out of scope.
    fn drop(&mut self) {
        if !self.ndpi_struct.is_null() {
            unsafe {
                ffi::ndpi_exit_detection_module(self.ndpi_struct);
            }
        }
    }
}
