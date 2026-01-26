use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use libc;

use wfb_ng::version::WFB_VERSION;

fn warn_entropy() {
    let path = CString::new("/dev/random").unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            let mut cnt: libc::c_int = 0;
            if libc::ioctl(fd, libc::RNDGETENTCNT, &mut cnt) == 0 && cnt < 160 {
                eprintln!("This system doesn't provide enough entropy to quickly generate high-quality random numbers.");
                eprintln!("Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.");
                eprintln!("On virtualized Linux environments, also consider using virtio-rng.");
                eprintln!("This command will wait until enough entropy has been collected.");
            }
            libc::close(fd);
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let password = match args.len() {
        1 => None,
        2 => Some(args[1].clone()),
        _ => {
            eprintln!("Usage: {} [password]", args[0]);
            eprintln!("WFB-ng version {}", WFB_VERSION);
            return Ok(());
        }
    };

    warn_entropy();

    unsafe {
        if libsodium_sys::sodium_init() < 0 {
            eprintln!("Libsodium init failed");
            std::process::exit(1);
        }
    }

    let mut drone_publickey = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
    let mut drone_secretkey = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];
    let mut gs_publickey = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
    let mut gs_secretkey = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];

    if let Some(pass) = password {
        let mut salt = [0u8; libsodium_sys::crypto_pwhash_argon2i_SALTBYTES as usize];
        let salt_bytes = b"wifibroadcastkey";
        salt[..salt_bytes.len()].copy_from_slice(salt_bytes);

        let mut seed = [0u8; libsodium_sys::crypto_box_SEEDBYTES as usize * 2];
        let rc = unsafe {
            libsodium_sys::crypto_pwhash_argon2i(
                seed.as_mut_ptr(),
                seed.len() as u64,
                pass.as_ptr() as *const _,
                pass.len() as u64,
                salt.as_ptr(),
                libsodium_sys::crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE as u64,
                libsodium_sys::crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
                libsodium_sys::crypto_pwhash_ALG_ARGON2I13 as i32,
            )
        };
        if rc != 0 {
            eprintln!("Unable to derive seed from password");
            std::process::exit(1);
        }

        let rc1 = unsafe {
            libsodium_sys::crypto_box_seed_keypair(
                drone_publickey.as_mut_ptr(),
                drone_secretkey.as_mut_ptr(),
                seed.as_ptr(),
            )
        };
        let rc2 = unsafe {
            libsodium_sys::crypto_box_seed_keypair(
                gs_publickey.as_mut_ptr(),
                gs_secretkey.as_mut_ptr(),
                seed.as_ptr().add(libsodium_sys::crypto_box_SEEDBYTES as usize),
            )
        };
        if rc1 != 0 || rc2 != 0 {
            eprintln!("Unable to derive keys");
            std::process::exit(1);
        }
        eprintln!("Keypair derived from provided password");
    } else {
        let rc1 = unsafe {
            libsodium_sys::crypto_box_keypair(
                drone_publickey.as_mut_ptr(),
                drone_secretkey.as_mut_ptr(),
            )
        };
        let rc2 = unsafe {
            libsodium_sys::crypto_box_keypair(
                gs_publickey.as_mut_ptr(),
                gs_secretkey.as_mut_ptr(),
            )
        };
        if rc1 != 0 || rc2 != 0 {
            eprintln!("Unable to generate keys");
            std::process::exit(1);
        }
        eprintln!("Keypair generated from random seed");
    }

    let mut drone_key = File::create("drone.key")?;
    drone_key.write_all(&drone_secretkey)?;
    drone_key.write_all(&gs_publickey)?;
    drone_key.flush()?;
    eprintln!("Drone keypair (drone sec + gs pub) saved to drone.key");

    let mut gs_key = File::create("gs.key")?;
    gs_key.write_all(&gs_secretkey)?;
    gs_key.write_all(&drone_publickey)?;
    gs_key.flush()?;
    eprintln!("GS keypair (gs sec + drone pub) saved to gs.key");

    Ok(())
}

