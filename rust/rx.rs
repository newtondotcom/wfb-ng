use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;

use libc;
use pcap_sys;

use crate::radiotap::{
    ieee80211_radiotap_iterator_init, ieee80211_radiotap_iterator_next,
    Ieee80211RadiotapIterator, IEEE80211_RADIOTAP_ANTENNA, IEEE80211_RADIOTAP_CHANNEL,
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL, IEEE80211_RADIOTAP_DBM_ANTNOISE, IEEE80211_RADIOTAP_FLAGS,
    IEEE80211_RADIOTAP_MCS, IEEE80211_RADIOTAP_TX_FLAGS, IEEE80211_RADIOTAP_VHT,
};
use crate::version::WFB_VERSION;
use crate::wifibroadcast::*;
use crate::{ipc_msg, ipc_msg_send, wfb_dbg, wfb_err};
use crate::zfex;

pub trait PacketLossListener {
    fn on_packet_loss(&mut self, lost_count: u32, last_seq: u32, new_seq: u32);
}

pub trait BaseAggregator {
    fn process_packet(
        &mut self,
        buf: &[u8],
        wlan_idx: u8,
        antenna: &[u8; RX_ANT_MAX],
        rssi: &[i8; RX_ANT_MAX],
        noise: &[i8; RX_ANT_MAX],
        freq: u16,
        mcs_index: u8,
        bandwidth: u8,
        sockaddr: Option<&libc::sockaddr_in>,
    );
    fn dump_stats(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxMode {
    Local,
    Forwarder,
    Aggregator,
}

const RX_RING_SIZE: usize = 40;
const DLT_IEEE802_11_RADIO: i32 = 127;

fn mod_n(x: i32, base: i32) -> i32 {
    (base + (x % base)) % base
}

fn parse_ipv4(addr: &str) -> io::Result<u32> {
    addr.parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv4 address"))
}

#[derive(Default)]
struct RxAntennaItem {
    count_all: i32,
    rssi_sum: i32,
    rssi_min: i8,
    rssi_max: i8,
    snr_sum: i32,
    snr_min: i8,
    snr_max: i8,
}

impl RxAntennaItem {
    fn log_rssi(&mut self, rssi: i8, noise: i8) {
        let snr = if noise != i8::MAX { rssi - noise } else { 0 };
        if self.count_all == 0 {
            self.rssi_min = rssi;
            self.rssi_max = rssi;
            self.snr_min = snr;
            self.snr_max = snr;
        } else {
            self.rssi_min = self.rssi_min.min(rssi);
            self.rssi_max = self.rssi_max.max(rssi);
            self.snr_min = self.snr_min.min(snr);
            self.snr_max = self.snr_max.max(snr);
        }
        self.rssi_sum += rssi as i32;
        self.snr_sum += snr as i32;
        self.count_all += 1;
    }
}

#[derive(Hash, PartialEq, Eq)]
struct RxAntennaKey {
    freq: u16,
    antenna_id: u64,
    mcs_index: u8,
    bandwidth: u8,
}

struct AlignedBuffer {
    ptr: *mut u8,
    size: usize,
}

impl AlignedBuffer {
    fn new(size: usize) -> io::Result<Self> {
        let mut out: *mut libc::c_void = ptr::null_mut();
        let rc = unsafe { libc::posix_memalign(&mut out, zfex::ZFEX_SIMD_ALIGNMENT, size) };
        if rc != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "posix_memalign failed",
            ));
        }
        Ok(Self {
            ptr: out as *mut u8,
            size,
        })
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.ptr as *mut _);
        }
    }
}

struct RxRingItem {
    block_idx: u64,
    fragments: Vec<AlignedBuffer>,
    fragment_map: Vec<usize>,
    fragment_to_send_idx: u8,
    has_fragments: u8,
}

impl RxRingItem {
    fn new() -> Self {
        Self {
            block_idx: 0,
            fragments: Vec::new(),
            fragment_map: Vec::new(),
            fragment_to_send_idx: 0,
            has_fragments: 0,
        }
    }
}

pub struct Forwarder {
    sockfd: i32,
    saddr: libc::sockaddr_in,
}

impl Forwarder {
    pub fn new(client_addr: &str, client_port: i32, snd_buf_size: i32) -> io::Result<Self> {
        let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sockfd < 0 {
            return Err(io::Error::last_os_error());
        }
        if snd_buf_size > 0 {
            let rc = unsafe {
                libc::setsockopt(
                    sockfd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &snd_buf_size as *const _ as *const _,
                    mem::size_of_val(&snd_buf_size) as u32,
                )
            };
            if rc != 0 {
                unsafe { libc::close(sockfd) };
                return Err(io::Error::last_os_error());
            }
        }

        let mut saddr: libc::sockaddr_in = unsafe { mem::zeroed() };
        saddr.sin_family = libc::AF_INET as u16;
        saddr.sin_addr.s_addr = parse_ipv4(client_addr)?;
        saddr.sin_port = (client_port as u16).to_be();

        Ok(Self { sockfd, saddr })
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sockfd);
        }
    }
}

impl BaseAggregator for Forwarder {
    fn process_packet(
        &mut self,
        buf: &[u8],
        wlan_idx: u8,
        antenna: &[u8; RX_ANT_MAX],
        rssi: &[i8; RX_ANT_MAX],
        noise: &[i8; RX_ANT_MAX],
        freq: u16,
        mcs_index: u8,
        bandwidth: u8,
        _sockaddr: Option<&libc::sockaddr_in>,
    ) {
        let mut fwd_hdr = Wrxfwd {
            wlan_idx,
            antenna: *antenna,
            rssi: *rssi,
            noise: *noise,
            freq: freq.to_be(),
            mcs_index,
            bandwidth,
        };

        let iov = [
            libc::iovec {
                iov_base: &mut fwd_hdr as *mut _ as *mut _,
                iov_len: mem::size_of::<Wrxfwd>(),
            },
            libc::iovec {
                iov_base: buf.as_ptr() as *mut _,
                iov_len: buf.len(),
            },
        ];

        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = &mut self.saddr as *mut _ as *mut _;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_in>() as u32;
        msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
        msg.msg_iovlen = iov.len();

        unsafe {
            libc::sendmsg(self.sockfd, &msg, libc::MSG_DONTWAIT);
        }
    }

    fn dump_stats(&mut self) {}
}

enum Sender {
    Udp { fd: i32, addr: libc::sockaddr_in },
    Unix { fd: i32, addr: libc::sockaddr_un, addr_len: u32 },
}

impl Sender {
    fn send(&self, payload: &[u8]) {
        match self {
            Sender::Udp { fd, addr } => unsafe {
                libc::sendto(
                    *fd,
                    payload.as_ptr() as *const _,
                    payload.len(),
                    libc::MSG_DONTWAIT,
                    addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as u32,
                );
            },
            Sender::Unix { fd, addr, addr_len } => unsafe {
                libc::sendto(
                    *fd,
                    payload.as_ptr() as *const _,
                    payload.len(),
                    libc::MSG_DONTWAIT,
                    addr as *const _ as *const libc::sockaddr,
                    *addr_len,
                );
            },
        }
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        match self {
            Sender::Udp { fd, .. } | Sender::Unix { fd, .. } => unsafe {
                libc::close(*fd);
            },
        }
    }
}

pub struct Aggregator {
    sender: Sender,
    antenna_stat: HashMap<RxAntennaKey, RxAntennaItem>,
    count_p_all: u32,
    count_b_all: u32,
    count_p_dec_err: u32,
    count_p_session: u32,
    count_p_data: u32,
    count_p_uniq: HashSet<u64>,
    count_p_fec_recovered: u32,
    count_p_lost: u32,
    count_p_bad: u32,
    count_p_override: u32,
    count_p_outgoing: u32,
    count_b_outgoing: u32,
    fec: Option<zfex::Fec>,
    fec_k: i32,
    fec_n: i32,
    session_hash: [u8; libsodium_sys::crypto_generichash_BYTES as usize],
    seq: u32,
    rx_ring: Vec<RxRingItem>,
    rx_ring_front: i32,
    rx_ring_alloc: i32,
    last_known_block: u64,
    epoch: u64,
    channel_id: u32,
    rx_secretkey: [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
    tx_publickey: [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    session_key: [u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize],
    packet_loss_listener: Option<Box<dyn PacketLossListener>>,
}

impl Aggregator {
    pub fn new_udp(
        client_addr: &str,
        client_port: i32,
        keypair: &str,
        epoch: u64,
        channel_id: u32,
        snd_buf_size: i32,
    ) -> io::Result<Self> {
        let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sockfd < 0 {
            return Err(io::Error::last_os_error());
        }
        if snd_buf_size > 0 {
            let rc = unsafe {
                libc::setsockopt(
                    sockfd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &snd_buf_size as *const _ as *const _,
                    mem::size_of_val(&snd_buf_size) as u32,
                )
            };
            if rc != 0 {
                unsafe { libc::close(sockfd) };
                return Err(io::Error::last_os_error());
            }
        }

        let mut saddr: libc::sockaddr_in = unsafe { mem::zeroed() };
        saddr.sin_family = libc::AF_INET as u16;
        saddr.sin_addr.s_addr = parse_ipv4(client_addr)?;
        saddr.sin_port = (client_port as u16).to_be();

        let sender = Sender::Udp { fd: sockfd, addr: saddr };
        Aggregator::new(sender, keypair, epoch, channel_id)
    }

    pub fn new_unix(
        socket_path: &str,
        keypair: &str,
        epoch: u64,
        channel_id: u32,
        snd_buf_size: i32,
    ) -> io::Result<Self> {
        let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        if sockfd < 0 {
            return Err(io::Error::last_os_error());
        }
        if snd_buf_size > 0 {
            let rc = unsafe {
                libc::setsockopt(
                    sockfd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &snd_buf_size as *const _ as *const _,
                    mem::size_of_val(&snd_buf_size) as u32,
                )
            };
            if rc != 0 {
                unsafe { libc::close(sockfd) };
                return Err(io::Error::last_os_error());
            }
        }

        let mut saddr: libc::sockaddr_un = unsafe { mem::zeroed() };
        saddr.sun_family = libc::AF_UNIX as u16;
        let path = socket_path.as_bytes();
        if path.len() + 1 >= saddr.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
        }
        unsafe {
            ptr::copy_nonoverlapping(
                path.as_ptr(),
                saddr.sun_path.as_mut_ptr().add(1) as *mut u8,
                path.len(),
            );
        }
        saddr.sun_path[0] = 0;

        let sender = Sender::Unix {
            fd: sockfd,
            addr: saddr,
            addr_len: (mem::size_of::<libc::sa_family_t>() + path.len() + 1) as u32,
        };
        Aggregator::new(sender, keypair, epoch, channel_id)
    }

    fn new(
        sender: Sender,
        keypair: &str,
        epoch: u64,
        channel_id: u32,
    ) -> io::Result<Self> {
        let mut rx_secretkey = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];
        let mut tx_publickey = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
        let mut file = std::fs::File::open(keypair)?;
        use std::io::Read;
        file.read_exact(&mut rx_secretkey)?;
        file.read_exact(&mut tx_publickey)?;

        Ok(Self {
            sender,
            antenna_stat: HashMap::new(),
            count_p_all: 0,
            count_b_all: 0,
            count_p_dec_err: 0,
            count_p_session: 0,
            count_p_data: 0,
            count_p_uniq: HashSet::new(),
            count_p_fec_recovered: 0,
            count_p_lost: 0,
            count_p_bad: 0,
            count_p_override: 0,
            count_p_outgoing: 0,
            count_b_outgoing: 0,
            fec: None,
            fec_k: -1,
            fec_n: -1,
            session_hash: [0u8; libsodium_sys::crypto_generichash_BYTES as usize],
            seq: 0,
            rx_ring: (0..RX_RING_SIZE).map(|_| RxRingItem::new()).collect(),
            rx_ring_front: 0,
            rx_ring_alloc: 0,
            last_known_block: u64::MAX,
            epoch,
            channel_id,
            rx_secretkey,
            tx_publickey,
            session_key: [0u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize],
            packet_loss_listener: None,
        })
    }

    pub fn set_packet_loss_listener(&mut self, listener: Box<dyn PacketLossListener>) {
        self.packet_loss_listener = Some(listener);
    }

    fn clear_stats(&mut self) {
        self.antenna_stat.clear();
        self.count_p_all = 0;
        self.count_b_all = 0;
        self.count_p_dec_err = 0;
        self.count_p_session = 0;
        self.count_p_data = 0;
        self.count_p_uniq.clear();
        self.count_p_fec_recovered = 0;
        self.count_p_lost = 0;
        self.count_p_bad = 0;
        self.count_p_override = 0;
        self.count_p_outgoing = 0;
        self.count_b_outgoing = 0;
    }

    fn init_fec(&mut self, k: u8, n: u8) {
        let fec = zfex::fec_new(k as u16, n as u16).expect("fec_new");
        self.fec = Some(fec);
        self.fec_k = k as i32;
        self.fec_n = n as i32;
        self.rx_ring_front = 0;
        self.rx_ring_alloc = 0;
        self.last_known_block = u64::MAX;
        self.seq = 0;

        for ring in &mut self.rx_ring {
            ring.block_idx = 0;
            ring.fragment_to_send_idx = 0;
            ring.has_fragments = 0;
            ring.fragments.clear();
            ring.fragment_map = vec![0usize; n as usize];
            let align = zfex::ZFEX_SIMD_ALIGNMENT;
            let aligned_size = (MAX_FEC_PAYLOAD + align - 1) & !(align - 1);
            for _ in 0..n {
                let buf = AlignedBuffer::new(aligned_size).expect("alloc");
                ring.fragments.push(buf);
            }
        }
    }

    fn deinit_fec(&mut self) {
        self.fec = None;
        self.fec_k = -1;
        self.fec_n = -1;
        for ring in &mut self.rx_ring {
            ring.fragments.clear();
            ring.fragment_map.clear();
        }
    }

    fn log_rssi(
        &mut self,
        sockaddr: Option<&libc::sockaddr_in>,
        wlan_idx: u8,
        ant: &[u8; RX_ANT_MAX],
        rssi: &[i8; RX_ANT_MAX],
        noise: &[i8; RX_ANT_MAX],
        freq: u16,
        mcs_index: u8,
        bandwidth: u8,
    ) {
        for i in 0..RX_ANT_MAX {
            if ant[i] == 0xff {
                break;
            }
            let mut antenna_id: u64 = 0;
            if let Some(addr) = sockaddr {
                if addr.sin_family as i32 == libc::AF_INET {
                    antenna_id = (u32::from_be(addr.sin_addr.s_addr) as u64) << 32;
                }
            }
            antenna_id |= (wlan_idx as u64) << 8 | ant[i] as u64;
            let key = RxAntennaKey {
                freq,
                antenna_id,
                mcs_index,
                bandwidth,
            };
            self.antenna_stat
                .entry(key)
                .or_insert_with(RxAntennaItem::default)
                .log_rssi(rssi[i], noise[i]);
        }
    }

    fn rx_ring_push(&mut self) -> i32 {
        if self.rx_ring_alloc < RX_RING_SIZE as i32 {
            let idx = mod_n(self.rx_ring_front + self.rx_ring_alloc, RX_RING_SIZE as i32);
            self.rx_ring_alloc += 1;
            return idx;
        }

        wfb_dbg!(
            "AGG: Override block 0x{:x} flush {} fragments\n",
            self.rx_ring[self.rx_ring_front as usize].block_idx,
            self.rx_ring[self.rx_ring_front as usize].has_fragments
        );
        self.count_p_override += 1;
        let ring_idx = self.rx_ring_front as usize;
        for f_idx in self.rx_ring[ring_idx].fragment_to_send_idx..(self.fec_k as u8) {
            let f = f_idx as usize;
            if self.rx_ring[ring_idx].fragment_map[f] != 0 {
                self.send_packet(ring_idx as i32, f_idx as i32);
            }
        }
        let idx = self.rx_ring_front;
        self.rx_ring_front = mod_n(self.rx_ring_front + 1, RX_RING_SIZE as i32);
        idx
    }

    fn get_block_ring_idx(&mut self, block_idx: u64) -> i32 {
        for i in 0..self.rx_ring_alloc {
            let idx = mod_n(self.rx_ring_front + i, RX_RING_SIZE as i32) as usize;
            if self.rx_ring[idx].block_idx == block_idx {
                return idx as i32;
            }
        }

        if self.last_known_block != u64::MAX && block_idx <= self.last_known_block {
            return -1;
        }

        let new_blocks = std::cmp::min(
            if self.last_known_block != u64::MAX {
                block_idx - self.last_known_block
            } else {
                1
            },
            RX_RING_SIZE as u64,
        ) as i32;
        self.last_known_block = block_idx;
        let mut ring_idx = -1;
        for i in 0..new_blocks {
            ring_idx = self.rx_ring_push();
            let idx = ring_idx as usize;
            self.rx_ring[idx].block_idx = block_idx + i as u64 + 1 - new_blocks as u64;
            self.rx_ring[idx].fragment_to_send_idx = 0;
            self.rx_ring[idx].has_fragments = 0;
            self.rx_ring[idx].fragment_map.fill(0);
        }
        ring_idx
    }

    fn send_packet(&mut self, ring_idx: i32, fragment_idx: i32) {
        let ring_idx = ring_idx as usize;
        let fragment_idx = fragment_idx as usize;
        let pkt_ptr = self.rx_ring[ring_idx].fragments[fragment_idx].as_mut_ptr();
        let packet_hdr = unsafe { ptr::read_unaligned(pkt_ptr as *const WpacketHdr) };
        let payload = unsafe { pkt_ptr.add(mem::size_of::<WpacketHdr>()) };
        let flags = packet_hdr.flags;
        let packet_size = u16::from_be(packet_hdr.packet_size) as usize;
        let packet_seq = self.rx_ring[ring_idx].block_idx * (self.fec_k as u64)
            + fragment_idx as u64;

        if packet_seq as u32 > self.seq + 1 && self.seq > 0 {
            let lost_count = (packet_seq as u32) - self.seq - 1;
            self.count_p_lost += lost_count;
            if let Some(listener) = self.packet_loss_listener.as_mut() {
                listener.on_packet_loss(lost_count, self.seq, packet_seq as u32);
            }
        }
        self.seq = packet_seq as u32;

        if packet_size > MAX_PAYLOAD_SIZE {
            wfb_err!("Corrupted packet {}\n", self.seq);
            self.count_p_bad += 1;
        } else if (flags & WFB_PACKET_FEC_ONLY) == 0 {
            let payload_slice = unsafe { std::slice::from_raw_parts(payload, packet_size) };
            self.sender.send(payload_slice);
            self.count_p_outgoing += 1;
            self.count_b_outgoing += packet_size as u32;
        }
    }

    fn apply_fec(&mut self, ring_idx: i32) {
        let ring_idx = ring_idx as usize;
        let fec = self.fec.as_ref().expect("fec");
        let fec_k = self.fec_k as usize;
        let fec_n = self.fec_n as usize;
        let mut index = vec![0u32; fec_k];
        let mut in_blocks = vec![ptr::null(); fec_k];
        let mut out_blocks = vec![ptr::null_mut(); fec_n - fec_k];
        let mut j = fec_k;
        let mut ob_idx = 0;
        let mut max_packet_size = 0usize;

        for i in 0..fec_k {
            if self.rx_ring[ring_idx].fragment_map[i] != 0 {
                in_blocks[i] = self.rx_ring[ring_idx].fragments[i].as_mut_ptr();
                index[i] = i as u32;
            } else {
                while j < fec_n && self.rx_ring[ring_idx].fragment_map[j] == 0 {
                    j += 1;
                }
                max_packet_size =
                    max_packet_size.max(self.rx_ring[ring_idx].fragment_map[j]);
                in_blocks[i] = self.rx_ring[ring_idx].fragments[j].as_mut_ptr();
                out_blocks[ob_idx] = self.rx_ring[ring_idx].fragments[i].as_mut_ptr();
                index[i] = j as u32;
                ob_idx += 1;
                j += 1;
            }
        }

        if max_packet_size == 0 || max_packet_size > MAX_FEC_PAYLOAD {
            return;
        }

        let aligned_size = (max_packet_size + zfex::ZFEX_SIMD_ALIGNMENT - 1)
            & !(zfex::ZFEX_SIMD_ALIGNMENT - 1);
        let rc = zfex::fec_decode_simd(
            fec,
            &mut in_blocks,
            &out_blocks,
            &mut index,
            aligned_size,
        );
        if rc != zfex::ZfexStatusCode::Ok {
            wfb_err!("FEC decode failed\n");
        }
    }
}

impl BaseAggregator for Aggregator {
    fn process_packet(
        &mut self,
        buf: &[u8],
        wlan_idx: u8,
        antenna: &[u8; RX_ANT_MAX],
        rssi: &[i8; RX_ANT_MAX],
        noise: &[i8; RX_ANT_MAX],
        freq: u16,
        mcs_index: u8,
        bandwidth: u8,
        sockaddr: Option<&libc::sockaddr_in>,
    ) {
        self.count_p_all += 1;
        self.count_b_all += buf.len() as u32;
        if buf.is_empty() {
            return;
        }
        if buf.len() > MAX_FORWARDER_PACKET_SIZE {
            wfb_err!("Long packet (fec payload)\n");
            self.count_p_bad += 1;
            return;
        }

        let mut session_tmp = vec![0u8; MAX_SESSION_PACKET_SIZE
            - libsodium_sys::crypto_box_MACBYTES as usize
            - mem::size_of::<WsessionHdr>()];
        let mut new_session_hash = [0u8; libsodium_sys::crypto_generichash_BYTES as usize];

        match buf[0] {
            WFB_PACKET_DATA => {
                let min_size = mem::size_of::<WblockHdr>()
                    + libsodium_sys::crypto_aead_chacha20poly1305_ABYTES as usize
                    + mem::size_of::<WpacketHdr>();
                if buf.len() < min_size {
                    wfb_err!("Short packet (fec header)\n");
                    self.count_p_bad += 1;
                    return;
                }
            }
            WFB_PACKET_SESSION => {
                let min_size = mem::size_of::<WsessionHdr>()
                    + mem::size_of::<WsessionData>()
                    + libsodium_sys::crypto_box_MACBYTES as usize;
                if buf.len() < min_size || buf.len() > MAX_SESSION_PACKET_SIZE {
                    wfb_err!("Invalid session key packet\n");
                    self.count_p_bad += 1;
                    return;
                }

                let hdr = unsafe { &*(buf.as_ptr() as *const WsessionHdr) };
                let rc = unsafe {
                    libsodium_sys::crypto_generichash(
                        new_session_hash.as_mut_ptr(),
                        new_session_hash.len(),
                        buf[mem::size_of::<WsessionHdr>()..].as_ptr(),
                        (buf.len() - mem::size_of::<WsessionHdr>()) as u64,
                        hdr.session_nonce.as_ptr(),
                        hdr.session_nonce.len(),
                    )
                };
                if rc != 0 {
                    self.count_p_dec_err += 1;
                    return;
                }

                if self.session_hash == new_session_hash {
                    self.count_p_session += 1;
                    return;
                }

                let rc = unsafe {
                    libsodium_sys::crypto_box_open_easy(
                        session_tmp.as_mut_ptr(),
                        buf[mem::size_of::<WsessionHdr>()..].as_ptr(),
                        (buf.len() - mem::size_of::<WsessionHdr>()) as u64,
                        hdr.session_nonce.as_ptr(),
                        self.tx_publickey.as_ptr(),
                        self.rx_secretkey.as_ptr(),
                    )
                };
                if rc != 0 {
                    wfb_err!("Unable to decrypt session key\n");
                    self.count_p_dec_err += 1;
                    return;
                }

                let new_session_data = unsafe { &*(session_tmp.as_ptr() as *const WsessionData) };
                let session_epoch = u64::from_be(new_session_data.epoch);
                if session_epoch < self.epoch {
                    wfb_err!(
                        "Session epoch doesn't match: {} < {}\n",
                        session_epoch,
                        self.epoch
                    );
                    self.count_p_dec_err += 1;
                    return;
                }
                if u32::from_be(new_session_data.channel_id) != self.channel_id {
                    wfb_err!(
                        "Session channel_id doesn't match: {} != {}\n",
                        u32::from_be(new_session_data.channel_id),
                        self.channel_id
                    );
                    self.count_p_dec_err += 1;
                    return;
                }
                if new_session_data.fec_type != WFB_FEC_VDM_RS {
                    wfb_err!("Unsupported FEC codec type: {}\n", new_session_data.fec_type);
                    self.count_p_dec_err += 1;
                    return;
                }
                if new_session_data.n < 1 || new_session_data.k < 1 || new_session_data.k > new_session_data.n {
                    wfb_err!("Invalid FEC K/N\n");
                    self.count_p_dec_err += 1;
                    return;
                }

                self.count_p_session += 1;
                if self.session_key != new_session_data.session_key {
                    self.epoch = session_epoch;
                    self.session_key.copy_from_slice(&new_session_data.session_key);
                    if self.fec.is_some() {
                        self.deinit_fec();
                    }
                    self.init_fec(new_session_data.k, new_session_data.n);
                    let ts = get_time_ms().unwrap_or(0);
                    ipc_msg!(
                        "{}\tSESSION\t{}:{}:{}:{}\n",
                        ts,
                        self.epoch,
                        WFB_FEC_VDM_RS,
                        self.fec_k,
                        self.fec_n
                    );
                    ipc_msg_send!();
                }

                self.session_hash.copy_from_slice(&new_session_hash);
                return;
            }
            _ => {
                wfb_err!("Unknown packet type 0x{:x}\n", buf[0]);
                self.count_p_bad += 1;
                return;
            }
        }

        let mut decrypted = vec![0u8; MAX_FEC_PAYLOAD];
        let mut decrypted_len: u64 = 0;
        let block_hdr = unsafe { &*(buf.as_ptr() as *const WblockHdr) };
        let data_nonce = block_hdr.data_nonce;
        let rc = unsafe {
            libsodium_sys::crypto_aead_chacha20poly1305_decrypt(
                decrypted.as_mut_ptr(),
                &mut decrypted_len,
                ptr::null_mut(),
                buf[mem::size_of::<WblockHdr>()..].as_ptr(),
                (buf.len() - mem::size_of::<WblockHdr>()) as u64,
                buf.as_ptr(),
                mem::size_of::<WblockHdr>() as u64,
                &data_nonce as *const _ as *const u8,
                self.session_key.as_ptr(),
            )
        };
        if rc != 0 {
            wfb_err!(
                "Unable to decrypt packet #0x{:x}\n",
                u64::from_be(block_hdr.data_nonce)
            );
            self.count_p_dec_err += 1;
            return;
        }

        self.count_p_data += 1;
        self.log_rssi(sockaddr, wlan_idx, antenna, rssi, noise, freq, mcs_index, bandwidth);

        let decrypted_len = decrypted_len as usize;
        if decrypted_len < mem::size_of::<WpacketHdr>() || decrypted_len > MAX_FEC_PAYLOAD {
            self.count_p_bad += 1;
            return;
        }

        let block_idx = u64::from_be(block_hdr.data_nonce) >> 8;
        let fragment_idx = (u64::from_be(block_hdr.data_nonce) & 0xff) as usize;
        self.count_p_uniq.insert(u64::from_be(block_hdr.data_nonce));

        if block_idx > MAX_BLOCK_IDX {
            wfb_err!("block_idx overflow\n");
            self.count_p_bad += 1;
            return;
        }
        if fragment_idx >= self.fec_n as usize {
            wfb_err!("Invalid fragment_idx: {}\n", fragment_idx);
            self.count_p_bad += 1;
            return;
        }

        let ring_idx = self.get_block_ring_idx(block_idx);
        if ring_idx < 0 {
            return;
        }
        let ring_idx_usize = ring_idx as usize;
        if self.rx_ring[ring_idx_usize].fragment_map[fragment_idx] != 0 {
            return;
        }

        unsafe {
            ptr::write_bytes(
                self.rx_ring[ring_idx_usize].fragments[fragment_idx].as_mut_ptr(),
                0,
                MAX_FEC_PAYLOAD,
            );
            ptr::copy_nonoverlapping(
                decrypted.as_ptr(),
                self.rx_ring[ring_idx_usize].fragments[fragment_idx].as_mut_ptr(),
                decrypted_len,
            );
        }
        self.rx_ring[ring_idx_usize].fragment_map[fragment_idx] = decrypted_len;
        self.rx_ring[ring_idx_usize].has_fragments += 1;

        if ring_idx == self.rx_ring_front {
            while (self.rx_ring[ring_idx_usize].fragment_to_send_idx as usize)
                < self.fec_k as usize
                && self.rx_ring[ring_idx_usize].fragment_map
                    [self.rx_ring[ring_idx_usize].fragment_to_send_idx as usize]
                    != 0
            {
                let idx = self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32;
                self.send_packet(ring_idx, idx);
                self.rx_ring[ring_idx_usize].fragment_to_send_idx += 1;
            }

            if self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32 == self.fec_k {
                self.rx_ring_front = mod_n(self.rx_ring_front + 1, RX_RING_SIZE as i32);
                self.rx_ring_alloc -= 1;
                return;
            }
        }

        if (self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32) < self.fec_k
            && self.rx_ring[ring_idx_usize].has_fragments as i32 == self.fec_k
        {
            let mut nrm = mod_n(ring_idx - self.rx_ring_front, RX_RING_SIZE as i32);
            while nrm > 0 {
                let front_idx = self.rx_ring_front as usize;
                for f_idx in self.rx_ring[front_idx].fragment_to_send_idx as i32..self.fec_k {
                    let f = f_idx as usize;
                    if self.rx_ring[front_idx].fragment_map[f] != 0 {
                        self.send_packet(self.rx_ring_front, f_idx);
                    }
                }
                self.rx_ring_front = mod_n(self.rx_ring_front + 1, RX_RING_SIZE as i32);
                self.rx_ring_alloc -= 1;
                nrm -= 1;
            }

            let mut f_idx = self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32;
            while f_idx < self.fec_k {
                if self.rx_ring[ring_idx_usize].fragment_map[f_idx as usize] == 0 {
                    self.apply_fec(ring_idx);
                    let mut fec_count = 0;
                    while f_idx < self.fec_k {
                        if self.rx_ring[ring_idx_usize].fragment_map[f_idx as usize] == 0 {
                            fec_count += 1;
                        }
                        f_idx += 1;
                    }
                    if fec_count > 0 {
                        self.count_p_fec_recovered += fec_count;
                        wfb_dbg!("FEC recovered {} packets\n", fec_count);
                    }
                    break;
                }
                f_idx += 1;
            }

            while (self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32) < self.fec_k {
                let idx = self.rx_ring[ring_idx_usize].fragment_to_send_idx as i32;
                self.send_packet(ring_idx, idx);
                self.rx_ring[ring_idx_usize].fragment_to_send_idx += 1;
            }

            self.rx_ring_front = mod_n(self.rx_ring_front + 1, RX_RING_SIZE as i32);
            self.rx_ring_alloc -= 1;
        }
    }

    fn dump_stats(&mut self) {
        let ts = get_time_ms().unwrap_or(0);
        for (key, item) in &self.antenna_stat {
            if item.count_all == 0 {
                continue;
            }
            ipc_msg!(
                "{}\tRX_ANT\t{}:{}:{}\t{:x}\t{}:{}:{}:{}:{}:{}:{}\n",
                ts,
                key.freq,
                key.mcs_index,
                key.bandwidth,
                key.antenna_id,
                item.count_all,
                item.rssi_min,
                item.rssi_sum / item.count_all,
                item.rssi_max,
                item.snr_min,
                item.snr_sum / item.count_all,
                item.snr_max
            );
        }
        ipc_msg!(
            "{}\tPKT\t{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}\n",
            ts,
            self.count_p_all,
            self.count_b_all,
            self.count_p_dec_err,
            self.count_p_session,
            self.count_p_data,
            self.count_p_uniq.len() as u32,
            self.count_p_fec_recovered,
            self.count_p_lost,
            self.count_p_bad,
            self.count_p_outgoing,
            self.count_b_outgoing
        );
        ipc_msg_send!();

        if self.count_p_override > 0 {
            wfb_err!("{} block overrides\n", self.count_p_override);
        }
        if self.count_p_lost > 0 {
            wfb_err!("{} packets lost\n", self.count_p_lost);
        }

        self.clear_stats();
    }
}

pub struct Receiver {
    wlan_idx: u8,
    fd: i32,
    pcap: *mut pcap_sys::pcap_t,
}

impl Receiver {
    pub fn new(
        wlan: &str,
        wlan_idx: u8,
        channel_id: u32,
        rcv_buf_size: i32,
    ) -> io::Result<Self> {
        let mut errbuf = vec![0i8; pcap_sys::PCAP_ERRBUF_SIZE as usize];
        let c_wlan = CString::new(wlan)?;
        let pcap = unsafe { pcap_sys::pcap_create(c_wlan.as_ptr(), errbuf.as_mut_ptr()) };
        if pcap.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unable to open interface in pcap",
            ));
        }

        unsafe {
            if rcv_buf_size > 0 && pcap_sys::pcap_set_buffer_size(pcap, rcv_buf_size) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_buffer_size failed"));
            }
            if pcap_sys::pcap_set_snaplen(pcap, MAX_PCAP_PACKET_SIZE as i32) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_snaplen failed"));
            }
            if pcap_sys::pcap_set_promisc(pcap, 1) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_promisc failed"));
            }
            if pcap_sys::pcap_set_timeout(pcap, -1) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_timeout failed"));
            }
            if pcap_sys::pcap_set_immediate_mode(pcap, 1) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_immediate_mode failed"));
            }
            if pcap_sys::pcap_activate(pcap) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "pcap_activate failed"));
            }
            if pcap_sys::pcap_setnonblock(pcap, 1, errbuf.as_mut_ptr()) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "set_nonblock failed"));
            }

            let link_encap = pcap_sys::pcap_datalink(pcap);
            if link_encap != DLT_IEEE802_11_RADIO {
                return Err(io::Error::new(io::ErrorKind::Other, "unknown encapsulation"));
            }

            let program = format!(
                "ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x{:08x}",
                channel_id
            );
            let mut bpfprogram: pcap_sys::bpf_program = mem::zeroed();
            if pcap_sys::pcap_compile(pcap, &mut bpfprogram, CString::new(program)?.as_ptr(), 1, 0)
                == -1
            {
                return Err(io::Error::new(io::ErrorKind::Other, "Unable to compile filter"));
            }
            if pcap_sys::pcap_setfilter(pcap, &mut bpfprogram) == -1 {
                pcap_sys::pcap_freecode(&mut bpfprogram);
                return Err(io::Error::new(io::ErrorKind::Other, "Unable to set filter"));
            }
            pcap_sys::pcap_freecode(&mut bpfprogram);
        }

        let fd = unsafe { pcap_sys::pcap_get_selectable_fd(pcap) };
        Ok(Self { wlan_idx, fd, pcap })
    }

    pub fn get_fd(&self) -> i32 {
        self.fd
    }

    pub fn loop_iter(&mut self, agg: &mut dyn BaseAggregator) -> io::Result<()> {
        loop {
            let mut hdr: pcap_sys::pcap_pkthdr = unsafe { mem::zeroed() };
            let pkt = unsafe { pcap_sys::pcap_next(self.pcap, &mut hdr) };
            if pkt.is_null() {
                break;
            }
            let mut pktlen = hdr.caplen as i32;
            let mut ant_idx = 0usize;
            let mut freq = 0u32;
            let mut antenna = [0xffu8; RX_ANT_MAX];
            let mut rssi = [i8::MIN; RX_ANT_MAX];
            let mut noise = [i8::MAX; RX_ANT_MAX];
            let mut flags: u8 = 0;
            let mut self_injected = false;
            let mut mcs_index: u8 = 0;
            let mut bandwidth: u8 = 20;

            let mut iterator: Ieee80211RadiotapIterator = unsafe { mem::zeroed() };
            let ret = unsafe {
                ieee80211_radiotap_iterator_init(
                    &mut iterator,
                    pkt as *mut _,
                    pktlen,
                    ptr::null(),
                )
            };
            if ret != 0 {
                continue;
            }
            let mut ret = 0;
            while ret == 0 && ant_idx < RX_ANT_MAX {
                ret = unsafe { ieee80211_radiotap_iterator_next(&mut iterator) };
                if ret != 0 {
                    continue;
                }
                match iterator.this_arg_index {
                    x if x == IEEE80211_RADIOTAP_ANTENNA => {
                        unsafe {
                            antenna[ant_idx] = *iterator.this_arg;
                        }
                        ant_idx += 1;
                    }
                    x if x == IEEE80211_RADIOTAP_CHANNEL => unsafe {
                        let val = ptr::read_unaligned(iterator.this_arg as *const u32);
                        freq = u32::from_le(val) & 0xffff;
                    },
                    x if x == IEEE80211_RADIOTAP_DBM_ANTSIGNAL => unsafe {
                        rssi[ant_idx] = *(iterator.this_arg as *const i8);
                    },
                    x if x == IEEE80211_RADIOTAP_DBM_ANTNOISE => unsafe {
                        noise[ant_idx] = *(iterator.this_arg as *const i8);
                    },
                    x if x == IEEE80211_RADIOTAP_FLAGS => unsafe {
                        flags = *iterator.this_arg;
                    },
                    x if x == IEEE80211_RADIOTAP_TX_FLAGS => {
                        self_injected = true;
                    }
                    x if x == IEEE80211_RADIOTAP_MCS => unsafe {
                        let mcs_have = *iterator.this_arg;
                        if (mcs_have & IEEE80211_RADIOTAP_MCS_HAVE_MCS as u8) != 0 {
                            mcs_index = *(iterator.this_arg.add(2)) & 0x7f;
                        }
                        if (mcs_have & 1) != 0 && (*(iterator.this_arg.add(1)) & 1) != 0 {
                            bandwidth = 40;
                        }
                    },
                    x if x == IEEE80211_RADIOTAP_VHT => unsafe {
                        let known = *iterator.this_arg;
                        if (known & 0x40) != 0 {
                            let bwidth = *(iterator.this_arg.add(3)) & 0x1f;
                            if bwidth >= 1 && bwidth <= 3 {
                                bandwidth = 40;
                            } else if bwidth >= 4 && bwidth <= 10 {
                                bandwidth = 80;
                            }
                        }
                        mcs_index = (*(iterator.this_arg.add(4)) >> 4) & 0x0f;
                    },
                    _ => {}
                }
            }

            if ret != -libc::ENOENT && ant_idx < RX_ANT_MAX {
                wfb_err!("Error parsing radiotap header!\n");
                continue;
            }

            if self_injected {
                continue;
            }
            if (flags & 0x10) != 0 {
                pktlen -= 4;
            }
            if (flags & 0x40) != 0 {
                wfb_err!("Got packet with bad fsc\n");
                continue;
            }

            let pkt = unsafe { pkt.add(iterator._max_length as usize) };
            pktlen -= iterator._max_length;
            if pktlen > mem::size_of_val(&IEEE80211_HEADER) as i32 {
                let payload = unsafe {
                    std::slice::from_raw_parts(
                        pkt.add(IEEE80211_HEADER.len()),
                        (pktlen as usize) - IEEE80211_HEADER.len(),
                    )
                };
                agg.process_packet(
                    payload,
                    self.wlan_idx,
                    &antenna,
                    &rssi,
                    &noise,
                    freq as u16,
                    mcs_index,
                    bandwidth,
                    None,
                );
            } else {
                wfb_err!("Short packet (ieee header)\n");
                continue;
            }
        }
        Ok(())
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            pcap_sys::pcap_close(self.pcap);
        }
    }
}

fn radio_loop(
    interfaces: &[String],
    channel_id: u32,
    agg: &mut dyn BaseAggregator,
    log_interval: i32,
    rcv_buf_size: i32,
) -> io::Result<()> {
    let mut rx_list: Vec<Receiver> = Vec::new();
    for (idx, iface) in interfaces.iter().enumerate() {
        rx_list.push(Receiver::new(iface, idx as u8, channel_id, rcv_buf_size)?);
    }
    let nfds = rx_list.len();
    let mut fds: Vec<libc::pollfd> = rx_list
        .iter()
        .map(|r| libc::pollfd {
            fd: r.get_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let mut log_send_ts = get_time_ms().unwrap_or(0);

    loop {
        let cur_ts = get_time_ms().unwrap_or(0);
        let timeout = if log_send_ts > cur_ts {
            (log_send_ts - cur_ts) as i32
        } else {
            0
        };
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds as u64, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        let cur_ts = get_time_ms().unwrap_or(0);
        if cur_ts >= log_send_ts {
            agg.dump_stats();
            log_send_ts = cur_ts + log_interval as u64 - ((cur_ts - log_send_ts) % log_interval as u64);
        }

        if rc == 0 {
            continue;
        }

        for i in 0..nfds {
            let revents = fds[i].revents;
            if revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "socket error"));
            }
            if revents & libc::POLLIN != 0 {
                rx_list[i].loop_iter(agg)?;
            }
        }
    }
}

fn network_loop(
    srv_port: i32,
    agg: &mut dyn BaseAggregator,
    log_interval: i32,
    rcv_buf_size: i32,
) -> io::Result<()> {
    let mut fwd_hdr: Wrxfwd = unsafe { mem::zeroed() };
    let mut sockaddr: libc::sockaddr_in;
    let mut buf = vec![0u8; MAX_FORWARDER_PACKET_SIZE];

    let mut log_send_ts = get_time_ms().unwrap_or(0);
    let fd = open_udp_socket_for_rx(srv_port, rcv_buf_size, 0, libc::SOCK_DGRAM, 0)?;

    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];

    loop {
        let cur_ts = get_time_ms().unwrap_or(0);
        let timeout = if log_send_ts > cur_ts {
            (log_send_ts - cur_ts) as i32
        } else {
            0
        };
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        let cur_ts = get_time_ms().unwrap_or(0);
        if cur_ts >= log_send_ts {
            agg.dump_stats();
            log_send_ts = cur_ts + log_interval as u64 - ((cur_ts - log_send_ts) % log_interval as u64);
        }

        if rc == 0 {
            continue;
        }

        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "socket error"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            loop {
                sockaddr = unsafe { mem::zeroed() };
                let mut iov = [
                    libc::iovec {
                        iov_base: &mut fwd_hdr as *mut _ as *mut _,
                        iov_len: mem::size_of::<Wrxfwd>(),
                    },
                    libc::iovec {
                        iov_base: buf.as_mut_ptr() as *mut _,
                        iov_len: buf.len(),
                    },
                ];
                let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };
                msghdr.msg_name = &mut sockaddr as *mut _ as *mut _;
                msghdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as u32;
                msghdr.msg_iov = iov.as_mut_ptr();
                msghdr.msg_iovlen = iov.len();
                let rsize = unsafe { libc::recvmsg(fd, &mut msghdr, libc::MSG_DONTWAIT) };
                if rsize < 0 {
                    break;
                }
                if rsize < mem::size_of::<Wrxfwd>() as isize {
                    continue;
                }
                let payload_len = rsize as usize - mem::size_of::<Wrxfwd>();
                agg.process_packet(
                    &buf[..payload_len],
                    fwd_hdr.wlan_idx,
                    &fwd_hdr.antenna,
                    &fwd_hdr.rssi,
                    &fwd_hdr.noise,
                    u16::from_be(fwd_hdr.freq),
                    fwd_hdr.mcs_index,
                    fwd_hdr.bandwidth,
                    Some(&sockaddr),
                );
            }
        }
    }
}

pub fn run(args: Vec<String>) -> i32 {
    let mut radio_port: u8 = 0;
    let mut link_id: u32 = 0;
    let mut epoch: u64 = 0;
    let mut log_interval = 1000;
    let mut client_port = 5600;
    let mut srv_port = 0;
    let mut client_addr = "127.0.0.1".to_string();
    let mut rx_mode = RxMode::Local;
    let mut rcv_buf = 0;
    let mut snd_buf = 0;
    let mut keypair = "rx.key".to_string();
    let mut unix_socket = String::new();

    let mut opts = getopts::Options::new();
    opts.optopt("K", "", "keypair", "KEY");
    opts.optflag("f", "", "forwarder");
    opts.optopt("a", "", "aggregator", "PORT");
    opts.optopt("c", "", "client addr", "ADDR");
    opts.optopt("u", "", "client port", "PORT");
    opts.optopt("U", "", "unix socket", "PATH");
    opts.optopt("p", "", "radio port", "PORT");
    opts.optopt("l", "", "log interval", "MS");
    opts.optopt("i", "", "link id", "ID");
    opts.optopt("e", "", "epoch", "EPOCH");
    opts.optopt("R", "", "rcv buf", "BYTES");
    opts.optopt("s", "", "snd buf", "BYTES");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("WFB-ng version {}, FEC: {}", WFB_VERSION, zfex::zfex_opt());
            return 1;
        }
    };

    if let Some(val) = matches.opt_str("K") {
        keypair = val;
    }
    if matches.opt_present("f") {
        rx_mode = RxMode::Forwarder;
    }
    if let Some(val) = matches.opt_str("a") {
        rx_mode = RxMode::Aggregator;
        srv_port = val.parse().unwrap_or(0);
    }
    if let Some(val) = matches.opt_str("c") {
        client_addr = val;
    }
    if let Some(val) = matches.opt_str("u") {
        client_port = val.parse().unwrap_or(client_port);
    }
    if let Some(val) = matches.opt_str("U") {
        unix_socket = val;
    }
    if let Some(val) = matches.opt_str("p") {
        radio_port = val.parse().unwrap_or(radio_port);
    }
    if let Some(val) = matches.opt_str("R") {
        rcv_buf = val.parse().unwrap_or(rcv_buf);
    }
    if let Some(val) = matches.opt_str("s") {
        snd_buf = val.parse().unwrap_or(snd_buf);
    }
    if let Some(val) = matches.opt_str("l") {
        log_interval = val.parse().unwrap_or(log_interval);
    }
    if let Some(val) = matches.opt_str("i") {
        link_id = val.parse::<u32>().unwrap_or(0) & 0xffffff;
    }
    if let Some(val) = matches.opt_str("e") {
        epoch = val.parse().unwrap_or(epoch);
    }

    unsafe {
        if libsodium_sys::sodium_init() < 0 {
            eprintln!("Libsodium init failed");
            return 1;
        }
    }

    let channel_id = (link_id << 8) + radio_port as u32;
    let interfaces = matches.free.clone();
    if rx_mode == RxMode::Aggregator {
        if interfaces.len() > 0 {
            // ok
        }
    } else if interfaces.is_empty() {
        eprintln!("No interfaces provided");
        return 1;
    }

    let mut agg_box: Box<dyn BaseAggregator> = match rx_mode {
        RxMode::Forwarder => Box::new(
            Forwarder::new(&client_addr, client_port, snd_buf).expect("forwarder"),
        ),
        _ => {
            if !unix_socket.is_empty() {
                Box::new(
                    Aggregator::new_unix(&unix_socket, &keypair, epoch, channel_id, snd_buf)
                        .expect("aggregator unix"),
                )
            } else {
                Box::new(
                    Aggregator::new_udp(&client_addr, client_port, &keypair, epoch, channel_id, snd_buf)
                        .expect("aggregator udp"),
                )
            }
        }
    };

    let res = if rx_mode == RxMode::Aggregator {
        network_loop(srv_port, agg_box.as_mut(), log_interval, rcv_buf)
    } else {
        radio_loop(&interfaces, channel_id, agg_box.as_mut(), log_interval, rcv_buf)
    };

    if let Err(err) = res {
        eprintln!("Error: {}", err);
        return 1;
    }
    0
}

