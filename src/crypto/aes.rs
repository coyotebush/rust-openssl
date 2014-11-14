use ffi;

#[repr(C)]
struct AesKey {
    rd_key: [u32,..60],
    rounds: i32,
}

impl AesKey {
    fn new() -> AesKey {
        AesKey{rd_key: [0u32,..60], rounds: 0}
    }
}

pub fn wrap(kek: &[u8], to_wrap: &[u8]) -> Vec<u8> {
    unsafe {
        let mut result = Vec::from_elem(to_wrap.len() + 8, 0u8);
        let mut aeskey = AesKey::new();
        ffi::AES_set_encrypt_key(kek.as_ptr(), (kek.len() * 8) as i32,
                                 ::std::mem::transmute(&mut aeskey));
        ffi::AES_wrap_key(::std::mem::transmute(&mut aeskey),
                          ::std::ptr::null(), result.as_mut_ptr(),
                          to_wrap.as_ptr(), to_wrap.len() as u32);
        result
    }
}

pub fn unwrap(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let unwrapped_len = wrapped.len() - 8;
        let mut result = Vec::from_elem(unwrapped_len, 0u8);
        let mut aeskey = AesKey::new();
        let ret =
            ffi::AES_set_decrypt_key(kek.as_ptr(), (kek.len() * 8) as i32,
                                     ::std::mem::transmute(&mut aeskey));
        if ret != 0 { return None }
        let ret =
            ffi::AES_unwrap_key(::std::mem::transmute(&mut aeskey),
                                ::std::ptr::null(), result.as_mut_ptr(),
                                wrapped.as_ptr(), wrapped.len() as u32);
        if ret != unwrapped_len as i32 { return None }
        Some(result)
    }
}

#[test]
fn test_wrap_unwrap() {
    let kek =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
         0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
         0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
    let to_wrap =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
         0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
         0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let expected =
        [0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3,
         0x5C, 0xFB, 0x87, 0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E,
         0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B, 0xFB,
         0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21];
    let wrapped = wrap(kek.as_slice(), to_wrap.as_slice());
    assert_eq!(wrapped.as_slice(), expected.as_slice());
    let unwrapped = unwrap(kek.as_slice(), expected.as_slice()).unwrap();
    assert_eq!(unwrapped.as_slice(), to_wrap.as_slice());
}
