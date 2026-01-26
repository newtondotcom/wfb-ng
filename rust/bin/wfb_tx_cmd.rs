use std::mem;
use std::ptr;

use libc;
use memoffset::offset_of;

use wfb_ng::tx_cmd::{
    CmdGetFec, CmdGetRadio, CmdReq, CmdResp, CmdSetFec, CmdSetRadio, CMD_GET_FEC, CMD_GET_RADIO,
    CMD_SET_FEC, CMD_SET_RADIO,
};
use wfb_ng::version::WFB_VERSION;

const COMMAND_TIMEOUT: u32 = 3;

extern "C" fn alarm_handler(_signum: i32) {
    let msg = b"Command timed out!\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const _, msg.len());
        libc::_exit(1);
    }
}

fn send_command(port: i32, req: &CmdReq, req_size: usize, resp: &mut CmdResp) -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        unsafe { libc::perror(b"socket\0".as_ptr() as *const _) };
        return 1;
    }

    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = (port as u16).to_be();
    addr.sin_addr.s_addr = u32::to_be(0x7f000001);

    unsafe {
        libc::alarm(COMMAND_TIMEOUT);
    }

    let psize = unsafe {
        libc::sendto(
            fd,
            req as *const _ as *const _,
            req_size,
            0,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of_val(&addr) as u32,
        )
    };
    if psize < 0 {
        unsafe { libc::perror(b"sendto\0".as_ptr() as *const _) };
        return 1;
    }

    *resp = CmdResp::zeroed();
    let psize = unsafe {
        libc::recv(
            fd,
            resp as *mut _ as *mut _,
            mem::size_of::<CmdResp>(),
            0,
        )
    };
    if psize < 0 {
        unsafe { libc::perror(b"recvfrom\0".as_ptr() as *const _) };
        return 1;
    }

    let resp_payload_size = match req.cmd_id {
        CMD_SET_FEC | CMD_SET_RADIO => 0,
        CMD_GET_FEC => mem::size_of::<CmdGetFec>(),
        CMD_GET_RADIO => mem::size_of::<CmdGetRadio>(),
        _ => 0,
    };

    if (psize as usize) < offset_of!(CmdResp, u) || resp.req_id != req.req_id {
        eprintln!("Invalid response");
        return 1;
    }

    let res = u32::from_be(resp.rc);
    if res != 0 {
        eprintln!("Command failed: {}", std::io::Error::from_raw_os_error(res as i32));
        return 1;
    }

    if (psize as usize) != offset_of!(CmdResp, u) + resp_payload_size {
        eprintln!("Invalid response");
        return 1;
    }

    0
}

fn set_fec(progname: &str, port: i32, args: &[String]) -> i32 {
    let mut k: u8 = 8;
    let mut n: u8 = 12;

    let mut opts = getopts::Options::new();
    opts.optopt("k", "", "RS_K", "RS_K");
    opts.optopt("n", "", "RS_N", "RS_N");
    opts.optflag("h", "", "help");
    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("Usage: {} <port> set_fec [-k RS_K] [-n RS_N]", progname);
            eprintln!("Default: k={}, n={}", k, n);
            eprintln!("WFB-ng version {}", WFB_VERSION);
            eprintln!("WFB-ng home page: <http://wfb-ng.org>");
            return 1;
        }
    };

    if matches.opt_present("h") {
        eprintln!("Usage: {} <port> set_fec [-k RS_K] [-n RS_N]", progname);
        eprintln!("Default: k={}, n={}", k, n);
        eprintln!("WFB-ng version {}", WFB_VERSION);
        eprintln!("WFB-ng home page: <http://wfb-ng.org>");
        return 1;
    }

    if let Some(val) = matches.opt_str("k") {
        k = val.parse().unwrap_or(k);
    }
    if let Some(val) = matches.opt_str("n") {
        n = val.parse().unwrap_or(n);
    }

    let mut req = CmdReq::zeroed();
    req.req_id = u32::to_be(unsafe { libc::rand() } as u32);
    req.cmd_id = CMD_SET_FEC;
    unsafe {
        req.u.cmd_set_fec = CmdSetFec { k, n };
    }
    let mut resp = CmdResp::zeroed();
    send_command(
        port,
        &req,
        offset_of!(CmdReq, u) + mem::size_of::<CmdSetFec>(),
        &mut resp,
    )
}

fn set_radio(progname: &str, port: i32, args: &[String]) -> i32 {
    let mut bandwidth = 20;
    let mut short_gi = 0;
    let mut stbc = 0;
    let mut ldpc = 0;
    let mut mcs_index = 1;
    let mut vht_nss = 1;
    let mut vht_mode = false;

    let mut opts = getopts::Options::new();
    opts.optopt("B", "", "bandwidth", "B");
    opts.optopt("G", "", "short_gi", "G");
    opts.optopt("S", "", "stbc", "S");
    opts.optopt("L", "", "ldpc", "L");
    opts.optopt("M", "", "mcs_index", "M");
    opts.optopt("N", "", "vht_nss", "N");
    opts.optflag("V", "", "vht_mode");
    opts.optflag("h", "", "help");
    let matches = match opts.parse(args) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("Usage: {} <port> set_radio [-B BW] [-G S/L] [-S STBC] [-L LDPC] [-M MCS] [-N NSS] [-V]", progname);
            eprintln!("WFB-ng version {}", WFB_VERSION);
            eprintln!("WFB-ng home page: <http://wfb-ng.org>");
            return 1;
        }
    };

    if matches.opt_present("h") {
        eprintln!("Usage: {} <port> set_radio [-B BW] [-G S/L] [-S STBC] [-L LDPC] [-M MCS] [-N NSS] [-V]", progname);
        eprintln!("WFB-ng version {}", WFB_VERSION);
        eprintln!("WFB-ng home page: <http://wfb-ng.org>");
        return 1;
    }

    if let Some(val) = matches.opt_str("B") {
        bandwidth = val.parse().unwrap_or(bandwidth);
        if bandwidth >= 80 {
            vht_mode = true;
        }
    }
    if let Some(val) = matches.opt_str("G") {
        short_gi = if val.starts_with('s') || val.starts_with('S') { 1 } else { 0 };
    }
    if let Some(val) = matches.opt_str("S") {
        stbc = val.parse().unwrap_or(stbc);
    }
    if let Some(val) = matches.opt_str("L") {
        ldpc = val.parse().unwrap_or(ldpc);
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

    let mut req = CmdReq::zeroed();
    req.req_id = u32::to_be(unsafe { libc::rand() } as u32);
    req.cmd_id = CMD_SET_RADIO;
    unsafe {
        req.u.cmd_set_radio = CmdSetRadio {
            stbc: stbc as u8,
            ldpc: ldpc != 0,
            short_gi: short_gi != 0,
            bandwidth: bandwidth as u8,
            mcs_index: mcs_index as u8,
            vht_mode,
            vht_nss: vht_nss as u8,
        };
    }
    let mut resp = CmdResp::zeroed();
    send_command(
        port,
        &req,
        offset_of!(CmdReq, u) + mem::size_of::<CmdSetRadio>(),
        &mut resp,
    )
}

fn get_fec(_progname: &str, port: i32, _args: &[String]) -> i32 {
    let mut req = CmdReq::zeroed();
    req.req_id = u32::to_be(unsafe { libc::rand() } as u32);
    req.cmd_id = CMD_GET_FEC;
    let mut resp = CmdResp::zeroed();
    let rc = send_command(port, &req, offset_of!(CmdReq, u), &mut resp);
    if rc == 0 {
        let fec = unsafe { resp.u.cmd_get_fec };
        println!("k={}\nn={}", fec.k, fec.n);
    }
    rc
}

fn get_radio(_progname: &str, port: i32, _args: &[String]) -> i32 {
    let mut req = CmdReq::zeroed();
    req.req_id = u32::to_be(unsafe { libc::rand() } as u32);
    req.cmd_id = CMD_GET_RADIO;
    let mut resp = CmdResp::zeroed();
    let rc = send_command(port, &req, offset_of!(CmdReq, u), &mut resp);
    if rc == 0 {
        let radio = unsafe { resp.u.cmd_get_radio };
        println!(
            "stbc={}\nldpc={}\nshort_gi={}\nbandwidth={}\nmcs_index={}\nvht_mode={}\nvht_nss={}",
            radio.stbc,
            radio.ldpc as u8,
            radio.short_gi as u8,
            radio.bandwidth,
            radio.mcs_index,
            radio.vht_mode as u8,
            radio.vht_nss
        );
    }
    rc
}

fn main() {
    unsafe {
        if libc::signal(libc::SIGALRM, alarm_handler as usize) == libc::SIG_ERR {
            libc::perror(b"signal\0".as_ptr() as *const _);
            std::process::exit(1);
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <port> {{set_fec | set_radio | get_fec | get_radio}} ...",
            args[0]
        );
        eprintln!("WFB-ng version {}", WFB_VERSION);
        eprintln!("WFB-ng home page: <http://wfb-ng.org>");
        std::process::exit(1);
    }

    unsafe {
        libc::srand(libc::time(ptr::null_mut()) as u32);
    }

    let port: i32 = args[1].parse().unwrap_or(0);
    let command = &args[2];
    let rest = &args[2..];

    let rc = match command.as_str() {
        "set_fec" => set_fec(&args[0], port, rest),
        "set_radio" => set_radio(&args[0], port, rest),
        "get_fec" => get_fec(&args[0], port, rest),
        "get_radio" => get_radio(&args[0], port, rest),
        _ => {
            eprintln!("Unknown command: {}", command);
            1
        }
    };

    std::process::exit(rc);
}

