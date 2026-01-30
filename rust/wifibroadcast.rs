use std::ffi::CString;
use std::io;
use std::mem;
use std::ptr;

use libc::{self, c_int, sockaddr_in, sockaddr_un, socklen_t};

#[macro_export]
macro_rules! string_format {
    ($($arg:tt)*) => {
        format!($($arg)*)
    };
}

#[macro_export]
macro_rules! wfb_dbg {
    ($($arg:tt)*) => {{
        if cfg!(debug_assertions) {
            eprint!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! wfb_err {
    ($($arg:tt)*) => {{
        eprint!($($arg)*);
    }};
}

#[macro_export]
macro_rules! wfb_info {
    ($($arg:tt)*) => {{
        eprint!($($arg)*);
    }};
}

#[macro_export]
macro_rules! ipc_msg {
    ($($arg:tt)*) => {{
        print!($($arg)*);
    }};
}

#[macro_export]
macro_rules! ipc_msg_send {
    () => {{
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }};
}

pub const IEEE80211_RADIOTAP_MCS_HAVE_BW: u8 = 0x01;
pub const IEEE80211_RADIOTAP_MCS_HAVE_MCS: u8 = 0x02;
pub const IEEE80211_RADIOTAP_MCS_HAVE_GI: u8 = 0x04;
pub const IEEE80211_RADIOTAP_MCS_HAVE_FMT: u8 = 0x08;
pub const IEEE80211_RADIOTAP_MCS_HAVE_FEC: u8 = 0x10;
pub const IEEE80211_RADIOTAP_MCS_HAVE_STBC: u8 = 0x20;

pub const IEEE80211_RADIOTAP_MCS_BW_20: u8 = 0;
pub const IEEE80211_RADIOTAP_MCS_BW_40: u8 = 1;
pub const IEEE80211_RADIOTAP_MCS_BW_20L: u8 = 2;
pub const IEEE80211_RADIOTAP_MCS_BW_20U: u8 = 3;
pub const IEEE80211_RADIOTAP_MCS_SGI: u8 = 0x04;
pub const IEEE80211_RADIOTAP_MCS_FMT_GF: u8 = 0x08;

pub const IEEE80211_RADIOTAP_MCS_FEC_LDPC: u8 = 0x10;
pub const IEEE80211_RADIOTAP_MCS_STBC_MASK: u8 = 0x60;
pub const IEEE80211_RADIOTAP_MCS_STBC_1: u8 = 1;
pub const IEEE80211_RADIOTAP_MCS_STBC_2: u8 = 2;
pub const IEEE80211_RADIOTAP_MCS_STBC_3: u8 = 3;
pub const IEEE80211_RADIOTAP_MCS_STBC_SHIFT: u8 = 5;

pub const IEEE80211_RADIOTAP_VHT_FLAG_STBC: u8 = 0x01;
pub const IEEE80211_RADIOTAP_VHT_FLAG_SGI: u8 = 0x04;
pub const IEEE80211_RADIOTAP_VHT_MCS_MASK: u8 = 0xF0;
pub const IEEE80211_RADIOTAP_VHT_NSS_MASK: u8 = 0x0F;
pub const IEEE80211_RADIOTAP_VHT_MCS_SHIFT: u8 = 4;
pub const IEEE80211_RADIOTAP_VHT_NSS_SHIFT: u8 = 0;
pub const IEEE80211_RADIOTAP_VHT_BW_20M: u8 = 0x00;
pub const IEEE80211_RADIOTAP_VHT_BW_40M: u8 = 0x01;
pub const IEEE80211_RADIOTAP_VHT_BW_80M: u8 = 0x04;
pub const IEEE80211_RADIOTAP_VHT_BW_160M: u8 = 0x0B;
pub const IEEE80211_RADIOTAP_VHT_CODING_LDPC_USER0: u8 = 0x01;

pub const MCS_KNOWN: u8 = IEEE80211_RADIOTAP_MCS_HAVE_MCS
    | IEEE80211_RADIOTAP_MCS_HAVE_BW
    | IEEE80211_RADIOTAP_MCS_HAVE_GI
    | IEEE80211_RADIOTAP_MCS_HAVE_STBC
    | IEEE80211_RADIOTAP_MCS_HAVE_FEC;

pub const RADIOTAP_HEADER_HT: [u8; 13] = [
    0x00, 0x00, // version
    0x0d, 0x00, // length
    0x00, 0x80, 0x08, 0x00, // present flags
    0x08, 0x00, // tx flags
    MCS_KNOWN, 0x00, 0x00,
];

pub const RADIOTAP_HEADER_VHT: [u8; 22] = [
    0x00, 0x00, // version
    0x16, 0x00, // length
    0x00, 0x80, 0x20, 0x00, // present flags
    0x08, 0x00, // tx flags
    0x45, 0x00, // vht known flags
    0x00, // flags
    0x04, // bw
    0x00, 0x00, 0x00, 0x00, // mcs nss
    0x00, // coding
    0x00, // group id
    0x00, 0x00, // partial aid
];

pub const WIFI_MTU: usize = 4045;
pub const PACKET_INJECTION_TIMEOUT_MS: u64 = 5;
pub const MAX_RX_INTERFACES: usize = 8;

pub const MCS_FLAGS_OFF: usize = 11;
pub const MCS_IDX_OFF: usize = 12;

pub const VHT_FLAGS_OFF: usize = 12;
pub const VHT_BW_OFF: usize = 13;
pub const VHT_MCSNSS0_OFF: usize = 14;
pub const VHT_CODING_OFF: usize = 18;

pub const SRC_MAC_THIRD_BYTE: usize = 12;
pub const DST_MAC_THIRD_BYTE: usize = 18;
pub const FRAME_SEQ_LB: usize = 22;
pub const FRAME_SEQ_HB: usize = 23;

pub const FRAME_TYPE_DATA: u8 = 0x08;
pub const FRAME_TYPE_RTS: u8 = 0xb4;

pub const IEEE80211_HEADER: [u8; 24] = [
    0x08, 0x01, 0x00, 0x00, // data frame
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,
    0x57, 0x42, 0xaa, 0xbb, 0xcc, 0xdd,
    0x00, 0x00,
];

pub const BLOCK_IDX_MASK: u64 = (1_u64 << 56) - 1;
pub const MAX_BLOCK_IDX: u64 = (1_u64 << 55) - 1;

pub const WFB_PACKET_DATA: u8 = 0x1;
pub const WFB_PACKET_SESSION: u8 = 0x2;
pub const WFB_FEC_VDM_RS: u8 = 0x1;
pub const WFB_PACKET_FEC_ONLY: u8 = 0x1;

pub const SESSION_KEY_ANNOUNCE_MSEC: u64 = 1000;
pub const RX_ANT_MAX: usize = 4;

pub const MAX_PAYLOAD_SIZE: usize = WIFI_MTU
    - IEEE80211_HEADER.len()
    - mem::size_of::<WblockHdr>()
    - (libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize)
    - mem::size_of::<WpacketHdr>();
pub const MAX_FEC_PAYLOAD: usize = WIFI_MTU
    - IEEE80211_HEADER.len()
    - mem::size_of::<WblockHdr>()
    - (libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize);
pub const MAX_FORWARDER_PACKET_SIZE: usize = WIFI_MTU - IEEE80211_HEADER.len();
pub const MAX_SESSION_PACKET_SIZE: usize = WIFI_MTU - IEEE80211_HEADER.len();
pub const MIN_DISTRIBUTION_PACKET_SIZE: usize =
    mem::size_of::<u32>() + RADIOTAP_HEADER_HT.len() + IEEE80211_HEADER.len();
pub const MAX_DISTRIBUTION_PACKET_SIZE: usize =
    mem::size_of::<u32>() + RADIOTAP_HEADER_VHT.len() + WIFI_MTU;
pub const MAX_PCAP_PACKET_SIZE: usize = WIFI_MTU + 256;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Wrxfwd {
    pub wlan_idx: u8,
    pub antenna: [u8; RX_ANT_MAX],
    pub rssi: [i8; RX_ANT_MAX],
    pub noise: [i8; RX_ANT_MAX],
    pub freq: u16,
    pub mcs_index: u8,
    pub bandwidth: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WsessionHdr {
    pub packet_type: u8,
    pub session_nonce: [u8; libsodium_sys::crypto_box_NONCEBYTES as usize],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WsessionData {
    pub epoch: u64,
    pub channel_id: u32,
    pub fec_type: u8,
    pub k: u8,
    pub n: u8,
    pub session_key: [u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize],
    pub tags: [u8; 0],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TlvHdr {
    pub id: u8,
    pub len: u16,
    pub value: [u8; 0],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WblockHdr {
    pub packet_type: u8,
    pub data_nonce: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WpacketHdr {
    pub flags: u8,
    pub packet_size: u16,
}

pub fn get_time_ms() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1000 + (ts.tv_nsec as u64) / 1_000_000)
}

pub fn get_time_us() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000 + (ts.tv_nsec as u64) / 1_000)
}

pub fn open_udp_socket_for_rx(
    port: i32,
    rcv_buf_size: i32,
    bind_addr: u32,
    socket_type: i32,
    socket_protocol: i32,
) -> io::Result<c_int> {
    let fd = unsafe { libc::socket(libc::AF_INET, socket_type, socket_protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let optval: c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const _,
            mem::size_of_val(&optval) as socklen_t,
        )
    } != 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &optval as *const _ as *const _,
            mem::size_of_val(&optval) as socklen_t,
        )
    } != 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    if rcv_buf_size > 0 {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcv_buf_size as *const _ as *const _,
                mem::size_of_val(&rcv_buf_size) as socklen_t,
            )
        } != 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
    }

    let mut saddr: sockaddr_in = unsafe { mem::zeroed() };
    saddr.sin_family = libc::AF_INET as u16;
    saddr.sin_addr.s_addr = u32::to_be(bind_addr);
    saddr.sin_port = (port as u16).to_be();

    if unsafe {
        libc::bind(
            fd,
            &saddr as *const _ as *const libc::sockaddr,
            mem::size_of::<sockaddr_in>() as socklen_t,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

pub fn open_unix_socket_for_rx(
    socket_path: &str,
    rcv_buf_size: i32,
    socket_type: i32,
    socket_protocol: i32,
) -> io::Result<c_int> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, socket_protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let optval: c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const _,
            mem::size_of_val(&optval) as socklen_t,
        )
    } != 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RXQ_OVFL,
            &optval as *const _ as *const _,
            mem::size_of_val(&optval) as socklen_t,
        )
    } != 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    if rcv_buf_size > 0 {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcv_buf_size as *const _ as *const _,
                mem::size_of_val(&rcv_buf_size) as socklen_t,
            )
        } != 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
    }

    let mut saddr: sockaddr_un = unsafe { mem::zeroed() };
    saddr.sun_family = libc::AF_UNIX as u16;
    let path = CString::new(socket_path).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path contains null")
    })?;
    let bytes = path.as_bytes();
    if bytes.len() + 1 > saddr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const _,
            saddr.sun_path.as_mut_ptr().add(1) as *mut _,
            bytes.len(),
        );
    }
    saddr.sun_path[0] = 0;

    let addr_len =
        (mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as socklen_t;
    if unsafe {
        libc::bind(
            fd,
            &saddr as *const _ as *const libc::sockaddr,
            addr_len,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

