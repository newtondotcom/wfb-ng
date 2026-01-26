use std::env;
use std::io::Write;

use glib::{ControlFlow, MainLoop};
use gstreamer as gst;
use gstreamer_rtsp_server as gst_rtsp_server;

use wfb_ng::version::WFB_VERSION;

fn usage(prog: &str, mtu: i32, uri: &str, rtsp_port: &str, rtp_port: i32, latency: i32) -> ! {
    eprintln!(
        "Usage: {} [-m mtu] [-u uri] [-p rtsp_port] [-P rtp_port] [-l latency] {{ h264 | h265 }}",
        prog
    );
    eprintln!(
        "Default: mtu={}, uri='{}', rtsp_port={}, rtp_port={}, latency={}",
        mtu, uri, rtsp_port, rtp_port, latency
    );
    eprintln!("WFB-ng version {}", WFB_VERSION);
    eprintln!("WFB-ng home page: <http://wfb-ng.org>");
    std::process::exit(1);
}

fn main() {
    let mut mtu = 1400;
    let mut latency = 0;
    let mut uri = "/wfb".to_string();
    let mut rtsp_port = "8554".to_string();
    let mut rtp_port = 5600;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-m" => {
                i += 1;
                mtu = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(mtu);
            }
            "-u" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    if val.starts_with('/') {
                        uri = val.clone();
                    } else {
                        usage(&args[0], mtu, &uri, &rtsp_port, rtp_port, latency);
                    }
                }
            }
            "-p" => {
                i += 1;
                if let Some(val) = args.get(i) {
                    rtsp_port = val.clone();
                }
            }
            "-P" => {
                i += 1;
                rtp_port = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(rtp_port);
            }
            "-l" => {
                i += 1;
                latency = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(latency);
            }
            _ if args[i].starts_with('-') => {
                usage(&args[0], mtu, &uri, &rtsp_port, rtp_port, latency);
            }
            _ => break,
        }
        i += 1;
    }

    if i >= args.len() {
        usage(&args[0], mtu, &uri, &rtsp_port, rtp_port, latency);
    }
    let mode_arg = &args[i];
    if mode_arg != "h264" && mode_arg != "h265" {
        usage(&args[0], mtu, &uri, &rtsp_port, rtp_port, latency);
    }
    let mode: i32 = mode_arg[1..].parse().unwrap_or(264);

    gst::init().expect("gst init");

    let main_loop = MainLoop::new(None, false);
    let server = gst_rtsp_server::RTSPServer::new();
    server.set_service(&rtsp_port);

    let mounts = server.mount_points().expect("mount points");
    let factory = gst_rtsp_server::RTSPMediaFactory::new();
    let pipeline = format!(
        "( udpsrc port={} ! application/x-rtp,media=video,clock-rate=90000,encoding-name=H{} \
         ! rtpjitterbuffer latency={} ! rtph{}depay ! rtph{}pay name=pay0 pt=96 \
         config-interval=1 aggregate-mode=zero-latency mtu={} )",
        rtp_port, mode, latency, mode, mode, mtu
    );
    println!("Pipeline: {}", pipeline);
    factory.set_launch(&pipeline);
    factory.set_shared(true);
    mounts.add_factory(&uri, factory);

    drop(mounts);

    if server.attach(None).is_none() {
        eprintln!("failed to attach the server");
        std::process::exit(1);
    }

    let server_clone = server.clone();
    glib::timeout_add_seconds_local(2, move || {
        if let Some(pool) = server_clone.session_pool() {
            pool.cleanup();
        }
        ControlFlow::Continue
    });

    println!(
        "H{} stream with mtu {} ready at rtsp://127.0.0.1:{}{}",
        mode, mtu, rtsp_port, uri
    );
    std::io::stdout().flush().ok();

    main_loop.run();
}

