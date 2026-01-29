use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::net::Ipv4Addr;
use std::process::Command;
use std::ptr;
use std::time::{Duration, Instant};

use libc;

use crate::version::WFB_VERSION;
use crate::wfb_dbg;

const MTU: usize = 1445;
const PING_INTERVAL_MS: u64 = 500;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TunPacketHdr {
    packet_size: u16,
}

struct InPacketBuffer {
    data: Vec<u8>,
    data_size: usize,
    batch_size: usize,
}

struct OutPacketBuffer {
    data: Vec<u8>,
    data_size: usize,
    offset: usize,
}

fn set_nonblock(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn open_tun(dev: &str, dev_addr: &str) -> io::Result<RawFd> {
    let path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    unsafe {
        let name_bytes = dev.as_bytes();
        let len = std::cmp::min(name_bytes.len(), ifr.ifr_name.len() - 1);
        ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const _,
            ifr.ifr_name.as_mut_ptr() as *mut _,
            len,
        );
    }
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &ifr) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    set_nonblock(fd)?;

    if !dev_addr.is_empty() {
        let iface = unsafe { std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr()) }
            .to_string_lossy()
            .to_string();
        let mtu = MTU - mem::size_of::<TunPacketHdr>();
        let status = Command::new("ip")
            .args(["link", "set", "up", "mtu", &mtu.to_string(), "dev", &iface])
            .status()?;
        if !status.success() {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::Other, "ip link failed"));
        }
        let status = Command::new("ip")
            .args(["addr", "add", dev_addr, "dev", &iface])
            .status()?;
        if !status.success() {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::Other, "ip addr add failed"));
        }
    }

    Ok(fd)
}

fn create_udpsock(bind_port: u16) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let optval: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const _,
            mem::size_of_val(&optval) as u32,
        )
    } != 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    let mut saddr: libc::sockaddr_in = unsafe { mem::zeroed() };
    saddr.sin_family = libc::AF_INET as u16;
    saddr.sin_addr.s_addr = u32::to_be(0);
    saddr.sin_port = bind_port.to_be();
    if unsafe {
        libc::bind(
            fd,
            &saddr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

fn send_ping(fd: RawFd, peer: &libc::sockaddr_in) {
    unsafe {
        libc::sendto(
            fd,
            ptr::null(),
            0,
            libc::MSG_DONTWAIT,
            peer as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        );
    }
}

fn handle_tun_read(
    fd: RawFd,
    buf: &mut InPacketBuffer,
    peer: &libc::sockaddr_in,
    sock_fd: RawFd,
    agg_timeout_ms: u32,
    flush: bool,
    pending_send: &mut bool,
    pkt_sem: &mut i32,
) -> io::Result<Option<Instant>> {
    if buf.data_size >= MTU {
        return Ok(None);
    }

    let start = buf.data_size + mem::size_of::<TunPacketHdr>();
    let max = MTU - mem::size_of::<TunPacketHdr>();
    let nread = unsafe {
        libc::read(
            fd,
            buf.data.as_mut_ptr().add(start) as *mut _,
            max,
        )
    };
    if nread <= 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        let hdr_ptr = buf.data.as_mut_ptr().add(buf.data_size) as *mut TunPacketHdr;
        (*hdr_ptr).packet_size = (nread as u16).to_be();
    }
    buf.data_size += mem::size_of::<TunPacketHdr>() + nread as usize;

    if buf.data_size <= MTU {
        buf.batch_size = buf.data_size;
    }

    wfb_dbg!(
        "tun_read: packet_size={}, batch_size={}, data_size={}\n",
        nread,
        buf.batch_size,
        buf.data_size
    );

    if buf.data_size >= MTU || agg_timeout_ms == 0 || flush {
        if send_batch(sock_fd, buf, peer, pkt_sem).is_ok() {
            *pending_send = false;
        } else {
            *pending_send = true;
        }
        return Ok(None);
    }

    Ok(Some(Instant::now() + Duration::from_millis(agg_timeout_ms as u64)))
}

fn send_batch(
    fd: RawFd,
    buf: &mut InPacketBuffer,
    peer: &libc::sockaddr_in,
    pkt_sem: &mut i32,
) -> io::Result<()> {
    if buf.batch_size == 0 {
        return Ok(());
    }

    *pkt_sem = 1;
    let sent = unsafe {
        libc::sendto(
            fd,
            buf.data.as_ptr() as *const _,
            buf.batch_size,
            libc::MSG_DONTWAIT,
            peer as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if sent < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(err);
        }
        return Err(err);
    }

    wfb_dbg!(
        "socket_write: batch_size={}, data_size={}\n",
        buf.batch_size,
        buf.data_size
    );

    if buf.data_size > buf.batch_size {
        let remaining = buf.data_size - buf.batch_size;
        buf.data.copy_within(buf.batch_size..buf.data_size, 0);
        buf.data_size = remaining;
        buf.batch_size = buf.data_size;
    } else {
        buf.data_size = 0;
        buf.batch_size = 0;
    }
    Ok(())
}

fn handle_socket_read(fd: RawFd, buf: &mut OutPacketBuffer) -> io::Result<()> {
    let nread = unsafe { libc::recv(fd, buf.data.as_mut_ptr() as *mut _, MTU, libc::MSG_DONTWAIT) };
    if nread < 0 {
        return Err(io::Error::last_os_error());
    }
    if nread == 0 {
        wfb_dbg!("got ping\n");
        return Ok(());
    }
    buf.offset = 0;
    buf.data_size = nread as usize;
    wfb_dbg!(
        "socket_read: off={}, data_size={}\n",
        buf.offset,
        buf.data_size
    );
    Ok(())
}

fn handle_tun_write(fd: RawFd, buf: &mut OutPacketBuffer) -> io::Result<()> {
    while buf.offset < buf.data_size {
        if buf.data_size - buf.offset < mem::size_of::<TunPacketHdr>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short packet header"));
        }
        let hdr = unsafe {
            ptr::read_unaligned(
                buf.data.as_ptr().add(buf.offset) as *const TunPacketHdr
            )
        };
        let pkt_size = u16::from_be(hdr.packet_size) as usize;
        let pkt_start = buf.offset + mem::size_of::<TunPacketHdr>();
        let pkt_end = pkt_start + pkt_size;
        if pkt_end > buf.data_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short packet payload"));
        }

        let wrote = unsafe {
            libc::write(
                fd,
                buf.data.as_ptr().add(pkt_start) as *const _,
                pkt_size,
            )
        };
        if wrote < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            return Err(err);
        }

        buf.offset = pkt_end;
    }
    buf.offset = 0;
    buf.data_size = 0;
    Ok(())
}

pub fn run(args: Vec<String>) -> i32 {
    let mut agg_timeout_ms: u32 = 5;
    let mut bind_port: u16 = 5800;
    let mut tun_name = "wfb-tun".to_string();
    let mut tun_addr = "10.5.0.2/24".to_string();

    let mut peer_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    peer_addr.sin_family = libc::AF_INET as u16;
    peer_addr.sin_addr.s_addr = u32::to_be(0x7f000001);
    peer_addr.sin_port = (5801u16).to_be();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-t" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    tun_name = val.clone();
                }
            }
            "-a" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    tun_addr = val.clone();
                }
            }
            "-T" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    agg_timeout_ms = val.parse().unwrap_or(agg_timeout_ms);
                }
            }
            "-c" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    let ip: Ipv4Addr = match val.parse() {
                        Ok(ip) => ip,
                        Err(_) => {
                            eprintln!("invalid address");
                            return 1;
                        }
                    };
                    peer_addr.sin_addr.s_addr = u32::from(ip);
                }
            }
            "-u" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    peer_addr.sin_port = (val.parse::<u16>().unwrap_or(5801)).to_be();
                }
            }
            "-l" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    bind_port = val.parse().unwrap_or(bind_port);
                }
            }
            "-h" | "--help" => {
                eprintln!("Usage: {} [-t tun_name] [-a tun_addr] [-c peer_addr] [-u peer_port] [-l listen_port] [-T agg_timeout_ms]", args[0]);
                eprintln!(
                    "Default: tun_name={}, tun_addr={}, peer_addr=127.0.0.1, peer_port=5801, listen_port={}, agg_timeout_ms={}",
                    tun_name, tun_addr, bind_port, agg_timeout_ms
                );
                eprintln!("WFB-ng version {}", WFB_VERSION);
                eprintln!("WFB-ng home page: <http://wfb-ng.org>");
                return 0;
            }
            _ => {
                eprintln!("Usage: {} [-t tun_name] [-a tun_addr] [-c peer_addr] [-u peer_port] [-l listen_port] [-T agg_timeout_ms]", args[0]);
                eprintln!(
                    "Default: tun_name={}, tun_addr={}, peer_addr=127.0.0.1, peer_port=5801, listen_port={}, agg_timeout_ms={}",
                    tun_name, tun_addr, bind_port, agg_timeout_ms
                );
                eprintln!("WFB-ng version {}", WFB_VERSION);
                eprintln!("WFB-ng home page: <http://wfb-ng.org>");
                return 1;
            }
        }
        i += 1;
    }

    let sock_fd = match create_udpsock(bind_port) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("socket error: {}", err);
            return 1;
        }
    };
    let tun_fd = match open_tun(&tun_name, &tun_addr) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("tun error: {}", err);
            unsafe { libc::close(sock_fd) };
            return 1;
        }
    };

    let mut in_buf = InPacketBuffer {
        data: vec![0u8; MTU * 2],
        data_size: 0,
        batch_size: 0,
    };
    let mut out_buf = OutPacketBuffer {
        data: vec![0u8; MTU],
        data_size: 0,
        offset: 0,
    };

    let mut pkt_sem = 0;
    let mut next_ping = Instant::now() + Duration::from_millis(PING_INTERVAL_MS);
    let mut agg_deadline: Option<Instant> = None;
    let mut pending_send = false;

    loop {
        let now = Instant::now();
        if now >= next_ping {
            if pkt_sem == 0 {
                send_ping(sock_fd, &peer_addr);
            }
            if pkt_sem > 0 {
                pkt_sem -= 1;
            }
            next_ping = now + Duration::from_millis(PING_INTERVAL_MS);
        }

        if let Some(deadline) = agg_deadline {
            if now >= deadline {
                if send_batch(sock_fd, &mut in_buf, &peer_addr, &mut pkt_sem).is_ok() {
                    pending_send = false;
                } else {
                    pending_send = true;
                }
                agg_deadline = None;
            }
        }

        let mut pollfds = vec![
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sock_fd,
                events: libc::POLLIN | if pending_send { libc::POLLOUT } else { 0 },
                revents: 0,
            },
        ];
        if out_buf.data_size > out_buf.offset {
            pollfds.push(libc::pollfd {
                fd: tun_fd,
                events: libc::POLLOUT,
                revents: 0,
            });
        }

        let timeout = {
            let mut next = next_ping;
            if let Some(deadline) = agg_deadline {
                if deadline < next {
                    next = deadline;
                }
            }
            let dur = next.saturating_duration_since(Instant::now());
            if dur.is_zero() {
                0
            } else {
                dur.as_millis().min(i32::MAX as u128) as i32
            }
        };

        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as u64, timeout) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        if pollfds[0].revents & libc::POLLIN != 0 {
            if let Ok(deadline) = handle_tun_read(
                tun_fd,
                &mut in_buf,
                &peer_addr,
                sock_fd,
                agg_timeout_ms,
                false,
                &mut pending_send,
                &mut pkt_sem,
            ) {
                if deadline.is_some() {
                    agg_deadline = deadline;
                }
            }
        }

        if pollfds[1].revents & libc::POLLIN != 0 {
            if handle_socket_read(sock_fd, &mut out_buf).is_ok() {
                let _ = handle_tun_write(tun_fd, &mut out_buf);
            }
        }

        if pollfds[1].revents & libc::POLLOUT != 0 && pending_send {
            if send_batch(sock_fd, &mut in_buf, &peer_addr, &mut pkt_sem).is_ok() {
                pending_send = false;
            }
        }

        if pollfds.len() > 2 && pollfds[2].revents & libc::POLLOUT != 0 {
            let _ = handle_tun_write(tun_fd, &mut out_buf);
        }
    }

    unsafe {
        libc::close(tun_fd);
        libc::close(sock_fd);
    }
    0
}

