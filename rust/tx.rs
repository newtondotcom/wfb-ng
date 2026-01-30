use std::collections::HashMap;
use std::io;
use std::mem;
use std::ptr;
use std::time::Duration;

use libc;

use crate::version::WFB_VERSION;
use crate::wifibroadcast::*;
use crate::{ipc_msg, ipc_msg_send, wfb_dbg};
use crate::zfex;

#[derive(Clone, Debug)]
pub struct TagsItem {
    pub id: u8,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RadiotapHeader {
    pub header: Vec<u8>,
    pub stbc: u8,
    pub ldpc: bool,
    pub short_gi: bool,
    pub bandwidth: u8,
    pub mcs_index: u8,
    pub vht_mode: bool,
    pub vht_nss: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxMode {
    Local,
    Injector,
    Distributor,
}

fn aligned_size(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
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

pub fn init_radiotap_header(
    stbc: u8,
    ldpc: bool,
    short_gi: bool,
    bandwidth: u8,
    mcs_index: u8,
    vht_mode: bool,
    vht_nss: u8,
) -> io::Result<RadiotapHeader> {
    let mut res = RadiotapHeader {
        header: Vec::new(),
        stbc,
        ldpc,
        short_gi,
        bandwidth,
        mcs_index,
        vht_mode,
        vht_nss,
    };

    if !vht_mode {
        let mut flags = 0u8;
        match bandwidth {
            10 | 20 => flags |= IEEE80211_RADIOTAP_MCS_BW_20,
            40 => flags |= IEEE80211_RADIOTAP_MCS_BW_40,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported HT bandwidth: {}", bandwidth),
                ))
            }
        }
        if short_gi {
            flags |= IEEE80211_RADIOTAP_MCS_SGI;
        }
        match stbc {
            0 => {}
            1 => flags |= IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT,
            2 => flags |= IEEE80211_RADIOTAP_MCS_STBC_2 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT,
            3 => flags |= IEEE80211_RADIOTAP_MCS_STBC_3 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported HT STBC type: {}", stbc),
                ))
            }
        }
        if ldpc {
            flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
        }
        res.header.extend_from_slice(&RADIOTAP_HEADER_HT);
        res.header[MCS_FLAGS_OFF] = flags;
        res.header[MCS_IDX_OFF] = mcs_index;
    } else {
        res.header.extend_from_slice(&RADIOTAP_HEADER_VHT);
        let mut flags = 0u8;
        if short_gi {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_SGI;
        }
        if stbc > 0 {
            flags |= IEEE80211_RADIOTAP_VHT_FLAG_STBC;
        }
        match bandwidth {
            10 | 20 => res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_20M,
            40 => res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_40M,
            80 => res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_80M,
            160 => res.header[VHT_BW_OFF] = IEEE80211_RADIOTAP_VHT_BW_160M,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unsupported VHT bandwidth: {}", bandwidth),
                ))
            }
        }
        res.header[VHT_FLAGS_OFF] = flags;
        let mcs_nss = ((mcs_index & 0x0f) << IEEE80211_RADIOTAP_VHT_MCS_SHIFT)
            | ((vht_nss - 1) & 0x0f);
        res.header[VHT_MCSNSS0_OFF] = mcs_nss;
        if ldpc {
            res.header[VHT_CODING_OFF] = IEEE80211_RADIOTAP_VHT_CODING_LDPC_USER0;
        }
    }

    Ok(res)
}

pub struct TransmitterCore {
    fec: zfex::Fec,
    fec_k: usize,
    fec_n: usize,
    block_idx: u64,
    fragment_idx: usize,
    max_packet_size: usize,
    epoch: u64,
    channel_id: u32,
    fec_delay: u32,
    tx_secretkey: [u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize],
    rx_publickey: [u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize],
    session_key: [u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize],
    session_packet: [u8; MAX_SESSION_PACKET_SIZE],
    session_packet_size: usize,
    block: Vec<AlignedBuffer>,
    tags: Vec<TagsItem>,
}

impl TransmitterCore {
    pub fn new(
        k: usize,
        n: usize,
        keypair: &str,
        epoch: u64,
        channel_id: u32,
        fec_delay: u32,
        tags: Vec<TagsItem>,
    ) -> io::Result<Self> {
        let mut tx_secretkey = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];
        let mut rx_publickey = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
        let mut file = std::fs::File::open(keypair)?;
        use std::io::Read;
        file.read_exact(&mut tx_secretkey)?;
        file.read_exact(&mut rx_publickey)?;

        let mut core = TransmitterCore {
            fec: zfex::fec_new(k as u16, n as u16).expect("fec_new"),
            fec_k: k,
            fec_n: n,
            block_idx: 0,
            fragment_idx: 0,
            max_packet_size: 0,
            epoch,
            channel_id,
            fec_delay,
            tx_secretkey,
            rx_publickey,
            session_key: [0u8; libsodium_sys::crypto_aead_chacha20poly1305_KEYBYTES as usize],
            session_packet: [0u8; MAX_SESSION_PACKET_SIZE],
            session_packet_size: 0,
            block: Vec::new(),
            tags,
        };
        core.init_session(k as u8, n as u8)?;
        Ok(core)
    }

    fn init_session(&mut self, k: u8, n: u8) -> io::Result<()> {
        self.fec = zfex::fec_new(k as u16, n as u16).expect("fec_new");
        self.fec_k = k as usize;
        self.fec_n = n as usize;

        self.block.clear();
        let size = aligned_size(MAX_FEC_PAYLOAD, zfex::ZFEX_SIMD_ALIGNMENT);
        for _ in 0..self.fec_n {
            self.block.push(AlignedBuffer::new(size)?);
        }

        self.block_idx = 0;
        self.fragment_idx = 0;
        self.max_packet_size = 0;

        unsafe {
            libsodium_sys::randombytes_buf(
                self.session_key.as_mut_ptr() as *mut libc::c_void,
                self.session_key.len(),
            );
        }

        let session_hdr_ptr = self.session_packet.as_mut_ptr() as *mut WsessionHdr;
        unsafe {
            (*session_hdr_ptr).packet_type = WFB_PACKET_SESSION;
            libsodium_sys::randombytes_buf(
                (*session_hdr_ptr).session_nonce.as_mut_ptr() as *mut libc::c_void,
                (*session_hdr_ptr).session_nonce.len(),
            );
        }

        let mut tmp = vec![0u8; MAX_SESSION_PACKET_SIZE
            - libsodium_sys::crypto_box_MACBYTES as usize
            - mem::size_of::<WsessionHdr>()];
        let session_data_ptr = tmp.as_mut_ptr() as *mut WsessionData;
        unsafe {
            (*session_data_ptr).epoch = self.epoch.to_be();
            (*session_data_ptr).channel_id = self.channel_id.to_be();
            (*session_data_ptr).fec_type = WFB_FEC_VDM_RS;
            (*session_data_ptr).k = self.fec_k as u8;
            (*session_data_ptr).n = self.fec_n as u8;
            (*session_data_ptr)
                .session_key
                .copy_from_slice(&self.session_key);
        }

        let mut session_data_size = mem::size_of::<WsessionData>();
        for tag in &self.tags {
            let tlv_ptr = unsafe { tmp.as_mut_ptr().add(session_data_size) as *mut TlvHdr };
            unsafe {
                (*tlv_ptr).id = tag.id;
                (*tlv_ptr).len = tag.value.len() as u16;
                let value_ptr = (tlv_ptr as *mut u8).add(mem::size_of::<TlvHdr>());
                ptr::copy_nonoverlapping(tag.value.as_ptr(), value_ptr, tag.value.len());
            }
            session_data_size += mem::size_of::<TlvHdr>() + tag.value.len();
        }

        let session_hdr = unsafe { &*(self.session_packet.as_ptr() as *const WsessionHdr) };
        let rc = unsafe {
            libsodium_sys::crypto_box_easy(
                self.session_packet.as_mut_ptr().add(mem::size_of::<WsessionHdr>()),
                tmp.as_ptr(),
                session_data_size as u64,
                session_hdr.session_nonce.as_ptr(),
                self.rx_publickey.as_ptr(),
                self.tx_secretkey.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unable to make session key",
            ));
        }

        self.session_packet_size =
            mem::size_of::<WsessionHdr>() + session_data_size + libsodium_sys::crypto_box_MACBYTES as usize;
        Ok(())
    }

    fn send_block_fragment(&mut self, packet_size: usize, inject: &mut dyn FnMut(&[u8])) -> io::Result<()> {
        let mut ciphertext = vec![0u8; MAX_FORWARDER_PACKET_SIZE];
        let block_hdr_ptr = ciphertext.as_mut_ptr() as *mut WblockHdr;
        unsafe {
            (*block_hdr_ptr).packet_type = WFB_PACKET_DATA;
            (*block_hdr_ptr).data_nonce =
                (((self.block_idx & BLOCK_IDX_MASK) << 8) + self.fragment_idx as u64).to_be();
        }
        let mut ciphertext_len: u64 = 0;
        let rc = unsafe {
            libsodium_sys::crypto_aead_chacha20poly1305_encrypt(
                ciphertext.as_mut_ptr().add(mem::size_of::<WblockHdr>()),
                &mut ciphertext_len,
                self.block[self.fragment_idx].as_mut_ptr(),
                packet_size as u64,
                block_hdr_ptr as *const u8,
                mem::size_of::<WblockHdr>() as u64,
                ptr::null(),
                ptr::addr_of!((*block_hdr_ptr).data_nonce) as *const u8,
                self.session_key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "encrypt failed"));
        }
        let total = mem::size_of::<WblockHdr>() + ciphertext_len as usize;
        inject(&ciphertext[..total]);
        Ok(())
    }

    fn send_session_key(&self, inject: &mut dyn FnMut(&[u8])) {
        wfb_dbg!("Announce session key\n");
        inject(&self.session_packet[..self.session_packet_size]);
    }

    pub fn send_packet(
        &mut self,
        buf: Option<&[u8]>,
        flags: u8,
        inject: &mut dyn FnMut(&[u8]),
        set_mark: &mut dyn FnMut(u32),
    ) -> io::Result<bool> {
        let size = buf.map(|b| b.len()).unwrap_or(0);
        if self.fragment_idx == 0 && (flags & WFB_PACKET_FEC_ONLY) != 0 {
            return Ok(false);
        }

        let packet_ptr = self.block[self.fragment_idx].as_mut_ptr();
        let hdr_ptr = packet_ptr as *mut WpacketHdr;
        unsafe {
            (*hdr_ptr).flags = flags;
            (*hdr_ptr).packet_size = (size as u16).to_be();
        }
        if let Some(payload) = buf {
            unsafe {
                ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    packet_ptr.add(mem::size_of::<WpacketHdr>()),
                    payload.len(),
                );
            }
        }
        unsafe {
            ptr::write_bytes(
                packet_ptr.add(mem::size_of::<WpacketHdr>() + size),
                0,
                MAX_FEC_PAYLOAD - (mem::size_of::<WpacketHdr>() + size),
            );
        }

        if self.fragment_idx == 0 {
            set_mark(0);
        }
        self.send_block_fragment(mem::size_of::<WpacketHdr>() + size, inject)?;
        self.max_packet_size = self.max_packet_size.max(mem::size_of::<WpacketHdr>() + size);
        self.fragment_idx += 1;

        if self.fragment_idx < self.fec_k {
            return Ok(true);
        }

        let aligned = aligned_size(self.max_packet_size, zfex::ZFEX_SIMD_ALIGNMENT);
        let in_blocks: Vec<*const u8> = self
            .block
            .iter()
            .take(self.fec_k)
            .map(|b| b.as_mut_ptr() as *const u8)
            .collect();
        let out_blocks: Vec<*mut u8> = self
            .block
            .iter()
            .skip(self.fec_k)
            .map(|b| b.as_mut_ptr())
            .collect();
        let rc = zfex::fec_encode_simd(&self.fec, &in_blocks, &out_blocks, aligned);
        if rc != zfex::ZfexStatusCode::Ok {
            return Err(io::Error::new(io::ErrorKind::Other, "fec_encode failed"));
        }

        set_mark(1);
        while self.fragment_idx < self.fec_n {
            if self.fec_delay > 0 {
                std::thread::sleep(Duration::from_micros(self.fec_delay as u64));
            }
            self.send_block_fragment(self.max_packet_size, inject)?;
            self.fragment_idx += 1;
        }

        self.block_idx += 1;
        self.fragment_idx = 0;
        self.max_packet_size = 0;

        if self.block_idx > MAX_BLOCK_IDX {
            self.init_session(self.fec_k as u8, self.fec_n as u8)?;
            for _ in 0..(self.fec_n - self.fec_k + 1) {
                self.send_session_key(inject);
            }
        }
        Ok(true)
    }

    pub fn get_fec(&self) -> (usize, usize) {
        (self.fec_k, self.fec_n)
    }
}

#[derive(Default)]
struct TxAntennaItem {
    count_p_injected: u32,
    count_b_injected: u32,
    count_p_dropped: u32,
    latency_sum: u64,
    latency_min: u64,
    latency_max: u64,
}

impl TxAntennaItem {
    fn log_latency(&mut self, latency: u64, succeeded: bool, packet_size: usize) {
        if self.count_p_injected + self.count_p_dropped == 0 {
            self.latency_min = latency;
            self.latency_max = latency;
        } else {
            self.latency_min = self.latency_min.min(latency);
            self.latency_max = self.latency_max.max(latency);
        }
        self.latency_sum += latency;
        if succeeded {
            self.count_p_injected += 1;
            self.count_b_injected += packet_size as u32;
        } else {
            self.count_p_dropped += 1;
        }
    }
}

pub struct RawSocketInjector {
    sockfds: Vec<i32>,
    fd_fwmarks: HashMap<i32, u32>,
    use_qdisc: bool,
}

impl RawSocketInjector {
    pub fn new(wlans: &[String], use_qdisc: bool) -> io::Result<Self> {
        let mut sockfds = Vec::new();
        let mut fd_fwmarks = HashMap::new();
        for wlan in wlans {
            let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if !use_qdisc {
                let optval: libc::c_int = 1;
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_PACKET,
                        libc::PACKET_QDISC_BYPASS,
                        &optval as *const _ as *const _,
                        mem::size_of_val(&optval) as u32,
                    )
                };
                if rc != 0 {
                    unsafe { libc::close(fd) };
                    return Err(io::Error::last_os_error());
                }
            }

            let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
            unsafe {
                let bytes = wlan.as_bytes();
                let len = std::cmp::min(bytes.len(), ifr.ifr_name.len() - 1);
                ptr::copy_nonoverlapping(
                    bytes.as_ptr() as *const _,
                    ifr.ifr_name.as_mut_ptr() as *mut _,
                    len,
                );
            }
            if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &ifr) } < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
            sll.sll_family = libc::AF_PACKET as u16;
            unsafe {
                sll.sll_ifindex = ifr.ifr_ifru.ifru_ifindex;
            }
            sll.sll_protocol = 0;

            if unsafe {
                libc::bind(
                    fd,
                    &sll as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_ll>() as u32,
                )
            } < 0
            {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            sockfds.push(fd);
            fd_fwmarks.insert(fd, 0);
        }
        Ok(Self {
            sockfds,
            fd_fwmarks,
            use_qdisc,
        })
    }

    fn inject_packet(&mut self, wlan_idx: usize, buf: &[u8], fwmark: u32) -> io::Result<()> {
        let fd = self.sockfds[wlan_idx];
        if self.use_qdisc && *self.fd_fwmarks.get(&fd).unwrap_or(&0) != fwmark {
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &fwmark as *const _ as *const _,
                    mem::size_of_val(&fwmark) as u32,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            self.fd_fwmarks.insert(fd, fwmark);
        }

        let rc = unsafe { libc::send(fd, buf.as_ptr() as *const _, buf.len(), 0) };
        if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOBUFS) {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub struct RawSocketTransmitter {
    core: TransmitterCore,
    channel_id: u32,
    current_output: i32,
    ieee80211_seq: u16,
    injector: RawSocketInjector,
    antenna_stat: HashMap<u64, TxAntennaItem>,
    radiotap_header: RadiotapHeader,
    frame_type: u8,
    use_qdisc: bool,
    fwmark_base: u32,
    fwmark: u32,
}

impl RawSocketTransmitter {
    pub fn new(
        k: usize,
        n: usize,
        keypair: &str,
        epoch: u64,
        channel_id: u32,
        fec_delay: u32,
        tags: Vec<TagsItem>,
        wlans: &[String],
        radiotap_header: RadiotapHeader,
        frame_type: u8,
        use_qdisc: bool,
        fwmark_base: u32,
    ) -> io::Result<Self> {
        let core = TransmitterCore::new(k, n, keypair, epoch, channel_id, fec_delay, tags)?;
        let injector = RawSocketInjector::new(wlans, use_qdisc)?;
        Ok(Self {
            core,
            channel_id,
            current_output: 0,
            ieee80211_seq: 0,
            injector,
            antenna_stat: HashMap::new(),
            radiotap_header,
            frame_type,
            use_qdisc,
            fwmark_base,
            fwmark: fwmark_base,
        })
    }

    fn set_mark(&mut self, idx: u32) {
        self.fwmark = self.fwmark_base + idx;
    }

    pub fn select_output(&mut self, idx: i32) {
        self.current_output = idx;
    }

    pub fn update_radiotap_header(&mut self, header: RadiotapHeader) {
        self.radiotap_header = header;
    }

    pub fn get_radiotap_header(&self) -> RadiotapHeader {
        self.radiotap_header.clone()
    }

    fn inject_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut ieee_hdr = IEEE80211_HEADER;
        ieee_hdr[0] = self.frame_type;
        let channel_id_be = self.channel_id.to_be_bytes();
        ieee_hdr[SRC_MAC_THIRD_BYTE..SRC_MAC_THIRD_BYTE + 4].copy_from_slice(&channel_id_be);
        ieee_hdr[DST_MAC_THIRD_BYTE..DST_MAC_THIRD_BYTE + 4].copy_from_slice(&channel_id_be);
        ieee_hdr[FRAME_SEQ_LB] = (self.ieee80211_seq & 0xff) as u8;
        ieee_hdr[FRAME_SEQ_HB] = (self.ieee80211_seq >> 8) as u8;
        self.ieee80211_seq = self.ieee80211_seq.wrapping_add(16);

        let mut packet = Vec::with_capacity(self.radiotap_header.header.len() + ieee_hdr.len() + buf.len());
        packet.extend_from_slice(&self.radiotap_header.header);
        packet.extend_from_slice(&ieee_hdr);
        packet.extend_from_slice(buf);

        let start_us = get_time_us().unwrap_or(0);
        if self.current_output >= 0 {
            let idx = self.current_output as usize;
            let res = self.injector.inject_packet(idx, &packet, self.fwmark);
            let key = ((idx as u64) << 8) | 0xff;
            let succeeded = res.is_ok();
            self.antenna_stat
                .entry(key)
                .or_default()
                .log_latency(get_time_us().unwrap_or(0) - start_us, succeeded, buf.len());
            res?;
        } else {
            for idx in 0..self.injector.sockfds.len() {
                let res = self.injector.inject_packet(idx, &packet, self.fwmark);
                let key = ((idx as u64) << 8) | 0xff;
                let succeeded = res.is_ok();
                self.antenna_stat
                    .entry(key)
                    .or_default()
                    .log_latency(get_time_us().unwrap_or(0) - start_us, succeeded, buf.len());
                res?;
            }
        }
        Ok(())
    }

    pub fn send_packet(&mut self, buf: Option<&[u8]>, flags: u8) -> io::Result<bool> {
        let self_ptr: *mut RawSocketTransmitter = self;
        let mut inject = move |payload: &[u8]| unsafe {
            let _ = (*self_ptr).inject_packet(payload);
        };
        let mut set_mark = move |idx: u32| unsafe {
            (*self_ptr).set_mark(idx);
        };
        self.core.send_packet(buf, flags, &mut inject, &mut set_mark)
    }

    pub fn send_session_key(&mut self) {
        let self_ptr: *mut RawSocketTransmitter = self;
        let mut inject = move |payload: &[u8]| unsafe {
            let _ = (*self_ptr).inject_packet(payload);
        };
        self.core.send_session_key(&mut inject);
    }

    pub fn init_session(&mut self, k: usize, n: usize) -> io::Result<()> {
        self.core.init_session(k as u8, n as u8)
    }

    pub fn dump_stats(
        &mut self,
        ts: u64,
        injected_packets: &mut u32,
        dropped_packets: &mut u32,
        injected_bytes: &mut u32,
    ) {
        for (key, item) in &self.antenna_stat {
            if item.count_p_injected + item.count_p_dropped == 0 {
                continue;
            }
            ipc_msg!(
                "{}\tTX_ANT\t{:x}\t{}:{}:{}:{}:{}\n",
                ts,
                key,
                item.count_p_injected,
                item.count_p_dropped,
                item.latency_min,
                item.latency_sum / (item.count_p_injected + item.count_p_dropped) as u64,
                item.latency_max
            );
            *injected_packets += item.count_p_injected;
            *dropped_packets += item.count_p_dropped;
            *injected_bytes += item.count_b_injected;
        }
        self.antenna_stat.clear();
    }
}

pub fn run(args: Vec<String>) -> i32 {
    let mut k: usize = 8;
    let mut n: usize = 12;
    let mut radio_port: u8 = 0;
    let mut fec_delay: u32 = 0;
    let mut link_id: u32 = 0;
    let mut epoch: u64 = 0;
    let mut udp_port: i32 = 5600;
    let mut log_interval: i32 = 1000;
    let mut bandwidth: u8 = 20;
    let mut short_gi = false;
    let mut stbc: u8 = 0;
    let mut ldpc = false;
    let mut mcs_index: u8 = 1;
    let mut vht_nss: u8 = 1;
    let mut vht_mode = false;
    let mut keypair = "tx.key".to_string();
    let frame_type = FRAME_TYPE_DATA;
    let mut use_qdisc = false;
    let fwmark: u32 = 0;
    let mut tx_mode = TxMode::Local;

    let mut opts = getopts::Options::new();
    opts.optflag("d", "", "distributor");
    opts.optopt("I", "", "injector", "PORT");
    opts.optopt("K", "", "keypair", "KEY");
    opts.optopt("k", "", "k", "K");
    opts.optopt("n", "", "n", "N");
    opts.optopt("u", "", "udp_port", "PORT");
    opts.optopt("p", "", "radio_port", "PORT");
    opts.optopt("F", "", "fec_delay", "US");
    opts.optopt("l", "", "log_interval", "MS");
    opts.optopt("B", "", "bandwidth", "BW");
    opts.optopt("G", "", "short_gi", "S/L");
    opts.optopt("S", "", "stbc", "STBC");
    opts.optopt("L", "", "ldpc", "LDPC");
    opts.optopt("M", "", "mcs_index", "MCS");
    opts.optopt("N", "", "vht_nss", "NSS");
    opts.optflag("V", "", "vht_mode");
    opts.optflag("Q", "", "use_qdisc");
    opts.optopt("i", "", "link_id", "ID");
    opts.optopt("e", "", "epoch", "EPOCH");
    opts.optflag("R", "", "rcv_buf");
    opts.optflag("s", "", "snd_buf");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => return 1,
    };
    if matches.opt_present("d") {
        tx_mode = TxMode::Distributor;
    }
    if matches.opt_present("I") {
        tx_mode = TxMode::Injector;
    }
    if let Some(val) = matches.opt_str("K") {
        keypair = val;
    }
    if let Some(val) = matches.opt_str("k") {
        k = val.parse().unwrap_or(k);
    }
    if let Some(val) = matches.opt_str("n") {
        n = val.parse().unwrap_or(n);
    }
    if let Some(val) = matches.opt_str("u") {
        udp_port = val.parse().unwrap_or(udp_port);
    }
    if let Some(val) = matches.opt_str("p") {
        radio_port = val.parse().unwrap_or(radio_port);
    }
    if let Some(val) = matches.opt_str("F") {
        fec_delay = val.parse().unwrap_or(fec_delay);
    }
    if let Some(val) = matches.opt_str("l") {
        log_interval = val.parse().unwrap_or(log_interval);
    }
    if let Some(val) = matches.opt_str("B") {
        bandwidth = val.parse().unwrap_or(bandwidth);
        if bandwidth >= 80 {
            vht_mode = true;
        }
    }
    if let Some(val) = matches.opt_str("G") {
        short_gi = val.starts_with('s') || val.starts_with('S');
    }
    if let Some(val) = matches.opt_str("S") {
        stbc = val.parse().unwrap_or(stbc);
    }
    if let Some(val) = matches.opt_str("L") {
        ldpc = val.parse::<i32>().unwrap_or(0) != 0;
    }
    if let Some(val) = matches.opt_str("M") {
        mcs_index = val.parse().unwrap_or(mcs_index);
    }
    if let Some(val) = matches.opt_str("N") {
        vht_nss = val.parse().unwrap_or(vht_nss);
    }
    if matches.opt_present("V") {
        vht_mode = true;
    }
    if matches.opt_present("Q") {
        use_qdisc = true;
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

    if tx_mode != TxMode::Local {
        eprintln!("Only local mode is implemented in Rust port currently.");
        return 1;
    }

    let channel_id = (link_id << 8) + radio_port as u32;
    let interfaces = matches.free.clone();
    if interfaces.is_empty() {
        eprintln!("Usage: {} [options] interface1 [interface2] ...", args[0]);
        eprintln!("WFB-ng version {}", WFB_VERSION);
        return 1;
    }

    let radiotap_header = match init_radiotap_header(
        stbc,
        ldpc,
        short_gi,
        bandwidth,
        mcs_index,
        vht_mode,
        vht_nss,
    ) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("Failed to init radiotap header: {}", err);
            return 1;
        }
    };

    let mut tx = match RawSocketTransmitter::new(
        k,
        n,
        &keypair,
        epoch,
        channel_id,
        fec_delay,
        Vec::new(),
        &interfaces,
        radiotap_header,
        frame_type,
        use_qdisc,
        fwmark,
    ) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Failed to init transmitter: {}", err);
            return 1;
        }
    };

    let rx_fd = match open_udp_socket_for_rx(udp_port, 0, 0, libc::SOCK_DGRAM, 0) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("Unable to open UDP socket: {}", err);
            return 1;
        }
    };

    let mut fds = [libc::pollfd {
        fd: rx_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let mut log_send_ts = get_time_ms().unwrap_or(0);
    let mut count_p_injected = 0;
    let mut count_b_injected = 0;
    let mut count_p_dropped = 0;
    let mut count_p_incoming = 0;
    let mut count_b_incoming = 0;

    let mut buf = vec![0u8; MAX_PAYLOAD_SIZE];
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
            break;
        }

        let cur_ts = get_time_ms().unwrap_or(0);
        if cur_ts >= log_send_ts {
            tx.dump_stats(
                cur_ts,
                &mut count_p_injected,
                &mut count_p_dropped,
                &mut count_b_injected,
            );
            ipc_msg!(
                "{}\tPKT\t0:{}:{}:{}:{}:{}:{}\n",
                cur_ts,
                count_p_incoming,
                count_b_incoming,
                count_p_injected,
                count_b_injected,
                count_p_dropped,
                0u32
            );
            ipc_msg_send!();
            count_p_incoming = 0;
            count_b_incoming = 0;
            count_p_injected = 0;
            count_b_injected = 0;
            count_p_dropped = 0;
            log_send_ts = cur_ts + log_interval as u64 - ((cur_ts - log_send_ts) % log_interval as u64);
        }

        if rc == 0 {
            continue;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let rsize = unsafe {
                libc::recv(
                    rx_fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if rsize > 0 {
                count_p_incoming += 1;
                count_b_incoming += rsize as u32;
                let payload = &buf[..rsize as usize];
                if let Ok(sent) = tx.send_packet(Some(payload), 0) {
                    if sent {
                        count_p_injected += 1;
                        count_b_injected += payload.len() as u32;
                    }
                }
            }
        }
    }

    0
}

