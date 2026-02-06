use std::ffi::CStr;
use std::os::raw::c_char;

unsafe extern "C" {
    fn ndpi_revision() -> *const c_char;
}

pub fn rs_ndpi_revision() -> &'static str {
    let ptr = unsafe { ndpi_revision() };
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().unwrap()
}
