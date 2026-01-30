use wfb_ng::wifibroadcast::WsessionData;

fn randombytes(buf: &mut [u8]) {
    unsafe {
        libsodium_sys::randombytes_buf(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    }
}

fn main() {
    unsafe {
        if libsodium_sys::sodium_init() < 0 {
            eprintln!("Failed to initialize libsodium");
            std::process::exit(1);
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        println!("libsodium runtime accelerations:\n---");
        unsafe {
            println!(
                "SSE2:      {}",
                if libsodium_sys::sodium_runtime_has_sse2() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "SSSE3:     {}",
                if libsodium_sys::sodium_runtime_has_ssse3() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "SSE4.1:    {}",
                if libsodium_sys::sodium_runtime_has_sse41() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "AVX:       {}",
                if libsodium_sys::sodium_runtime_has_avx() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "AVX2:      {}",
                if libsodium_sys::sodium_runtime_has_avx2() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "AVX512F:   {}",
                if libsodium_sys::sodium_runtime_has_avx512f() != 0 {
                    "yes"
                } else {
                    "no"
                }
            );
        }
        println!("---");
    }

    // Basic crypto_aead_chacha20poly1305 test
    let mut key = [0u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize];
    let mut nonce = [0u8; libsodium_sys::crypto_aead_chacha20poly1305_NPUBBYTES as usize];
    let mut message = [0u8; 4096];
    let mut ad = [0u8; 32];
    let mut ciphertext =
        [0u8; 4096 + libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize];
    let mut decrypted = [0u8; 4096];

    unsafe {
        randombytes(&mut key);
        randombytes(&mut nonce);
        randombytes(&mut message);
        randombytes(&mut ad);

        let mut clen: u64 = 0;
        let rc = libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            &mut clen,
            message.as_ptr(),
            message.len() as u64,
            ad.as_ptr(),
            ad.len() as u64,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
        assert_eq!(rc, 0);

        let mut mlen: u64 = 0;
        let rc = libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
            decrypted.as_mut_ptr(),
            &mut mlen,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            clen,
            ad.as_ptr(),
            ad.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        );
        assert_eq!(rc, 0);
        assert_eq!(&message[..], &decrypted[..message.len()]);
    }

    // crypto_box test with session packet size
    let mut pk_sender = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
    let mut sk_sender = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];
    let mut pk_recipient = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
    let mut sk_recipient = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];

    let mut message = [0u8; std::mem::size_of::<WsessionData>()];
    let mut ciphertext =
        [0u8; std::mem::size_of::<WsessionData>() + libsodium_sys::crypto_box_MACBYTES as usize];
    let mut decrypted = [0u8; std::mem::size_of::<WsessionData>()];
    let mut nonce = [0u8; libsodium_sys::crypto_box_NONCEBYTES as usize];

    unsafe {
        libsodium_sys::crypto_box_keypair(pk_sender.as_mut_ptr(), sk_sender.as_mut_ptr());
        libsodium_sys::crypto_box_keypair(pk_recipient.as_mut_ptr(), sk_recipient.as_mut_ptr());
        randombytes(&mut message);
        randombytes(&mut nonce);

        let rc = libsodium_sys::crypto_box_easy(
            ciphertext.as_mut_ptr(),
            message.as_ptr(),
            message.len() as u64,
            nonce.as_ptr(),
            pk_recipient.as_ptr(),
            sk_sender.as_ptr(),
        );
        assert_eq!(rc, 0);

        let rc = libsodium_sys::crypto_box_open_easy(
            decrypted.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            pk_sender.as_ptr(),
            sk_recipient.as_ptr(),
        );
        assert_eq!(rc, 0);
        assert_eq!(&message[..], &decrypted[..]);
    }
}

