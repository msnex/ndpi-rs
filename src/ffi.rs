unsafe extern "C" {
    pub fn ndpi_revision() -> *const libc::c_char;
    pub fn ndpi_get_api_version() -> u16;
    pub fn ndpi_get_gcrypt_version() -> *const libc::c_char;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn ndpi_revision_test() {
        let ptr = unsafe { ndpi_revision() };
        assert!(!ptr.is_null());

        let c_str = unsafe { CStr::from_ptr(ptr) };
        let version = c_str.to_str().unwrap();
        let major = version.as_bytes()[0];
        assert!(major >= 5);
    }

    #[test]
    fn ndpi_api_version_test() {
        let api_version = unsafe { ndpi_get_api_version() };
        assert!(api_version > 0);
    }

    #[test]
    fn ndpi_gcrypt_version_test() {
        let ptr = unsafe { ndpi_get_gcrypt_version() };
        assert!(!ptr.is_null());

        let c_str = unsafe { CStr::from_ptr(ptr) };
        let version = c_str.to_str().unwrap();
        let major = version.as_bytes()[0];
        assert!(major >= 1);
    }
}
