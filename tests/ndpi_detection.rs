use ndpi_rs::{NdpiDetection, NdpiGlobalCtx};
use std::ffi::CStr;

fn get_config(ndpi: &NdpiDetection, proto: Option<&CStr>, param: &CStr) -> String {
    let res = ndpi.get_config(proto, param);
    assert!(res.is_ok());
    res.unwrap()
}

#[test]
fn ndpi_detection_config_test() {
    let res = NdpiDetection::new(None);
    assert!(res.is_ok());
    let mut ndpi = res.unwrap();

    let param = CStr::from_bytes_with_nul(b"packets_limit_per_flow\0").unwrap();
    let res = ndpi.set_config_u64(None, param, 64);
    assert!(res.is_ok());
    let value = get_config(&ndpi, None, param);
    assert_eq!(value, "64");

    let param = CStr::from_bytes_with_nul(b"log.level\0").unwrap();
    let value = CStr::from_bytes_with_nul(b"1\0").unwrap();
    let res = ndpi.set_config(None, param, value);
    assert!(res.is_ok());
    let value = get_config(&ndpi, None, param);
    assert_eq!(value, "1");

    let proto = CStr::from_bytes_with_nul(b"rtp\0").unwrap();
    let param = CStr::from_bytes_with_nul(b"max_packets_extra_dissection\0").unwrap();
    let value = CStr::from_bytes_with_nul(b"64\0").unwrap();
    let res = ndpi.set_config(Some(proto), param, value);
    assert!(res.is_ok());
    let value = get_config(&ndpi, Some(proto), param);
    assert_eq!(value, "64");

    // set error
    let param = CStr::from_bytes_with_nul(b"req.body.len\0").unwrap();
    let value = CStr::from_bytes_with_nul(b"64\0").unwrap();
    let res = ndpi.set_config(None, param, value);
    assert_eq!(res.err(), Some(ndpi_rs::ndpi_cfg_error::NDPI_CFG_NOT_FOUND));

    let res = ndpi.finalize();
    assert!(res.is_ok());

    // get error
    let param = CStr::from_bytes_with_nul(b"req.body.len\0").unwrap();
    let res = ndpi.get_config(None, param);
    assert_eq!(res.err(), Some(ndpi_rs::ndpi_cfg_error::NDPI_CFG_NOT_FOUND));
}

#[test]
fn ndpi_global_ctx_test() {
    let res = NdpiGlobalCtx::new();
    assert!(res.is_ok());
    let g_ctx = res.unwrap();

    let res = NdpiDetection::new(Some(&g_ctx));
    assert!(res.is_ok());
    let mut ndpi = res.unwrap();

    let param = CStr::from_bytes_with_nul(b"packets_limit_per_flow\0").unwrap();
    let res = ndpi.set_config_u64(None, param, 64);
    assert!(res.is_ok());
    let value = get_config(&ndpi, None, param);
    assert_eq!(value, "64");

    let res = ndpi.finalize();
    assert!(res.is_ok());
}
