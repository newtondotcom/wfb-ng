fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rc = wfb_ng::rx::run(args);
    std::process::exit(rc);
}

