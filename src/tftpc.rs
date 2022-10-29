/*
 * Copyright 2019-2020 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use getopts::Options;

#[allow(clippy::upper_case_acronyms)]
enum Operation {
    RRQ,
    WRQ,
}

struct Configuration {
    operation: Operation,
    mode: rtftp::Mode,
    filename: PathBuf,
    remote: SocketAddr,
    blksize: usize,
}

struct Tftpc {
    tftp: rtftp::Tftp,
    conf: Configuration,
}

fn update_progress(current: u64, total: u64, last: u64) -> u64 {
    if total == 0 {
        /* unknown; remote does not support tsize */
        return 0;
    }
    let onepercent = total / 100;
    if current < total && current < last + onepercent {
        /* not enough progress to warrant an update */
        return last;
    }

    let percent = 100 * current / total;
    print!("\r {}% ", percent);
    io::stdout().flush().expect("flushing stdout failed");
    if current >= total {
        print!("\r");
    }
    current
}

impl Tftpc {
    pub fn new(conf: Configuration) -> Tftpc {
        let mut tftp = rtftp::Tftp::new();
        tftp.set_mode(conf.mode);
        Tftpc {
            tftp,
            conf,
        }
    }

    fn wait_for_option_ack(&mut self, sock: &UdpSocket) -> Option<SocketAddr> {
        let mut buf = [0; 512];
        sock.peek_from(&mut buf).ok()?;
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        if opcode != rtftp::Opcode::OACK as u16 {
            return None;
        }

        let (len, remote) = sock.recv_from(&mut buf).ok()?;

        let mut options = self.tftp.parse_options(&buf[2..len]);
        self.tftp.init_tftp_options(sock, &mut options).ok()?;

        Some(remote)
    }

    fn wait_for_response(&self, sock: &UdpSocket, expected_opcode: rtftp::Opcode, expected_block: u16, expected_remote: Option<SocketAddr>) -> Result<Option<SocketAddr>, std::io::Error> {
        let mut buf = [0; 4];
        let (len, remote) = sock.peek_from(&mut buf)?;

        if let Some(rem) = expected_remote {
            /* verify we got a response from the same client that sent
               an optional previous option ack */
            if rem != remote {
                return Ok(None);
            }
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

        if opcode == rtftp::Opcode::ERROR as u16 {
            let mut buf = [0; 512];
            let len = sock.recv(&mut buf)?;
            return Err(self.tftp.parse_error(&buf[..len]));
        }

        /* first data packet is expected to be block 1 */
        if len != 4 || opcode != expected_opcode as u16 || block_nr != expected_block {
            return Ok(None);
        }

        Ok(Some(remote))
    }

    fn append_option_req(&self, buf: &mut Vec<u8>, fsize: u64) {
        self.tftp.append_option(buf, "blksize", &format!("{}", self.conf.blksize));
        self.tftp.append_option(buf, "timeout", &format!("{}", 3));
        self.tftp.append_option(buf, "tsize", &format!("{}", fsize));
    }

    fn init_req(&self, opcode: rtftp::Opcode, filename: &str, size: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend((opcode as u16).to_be_bytes().iter());
        let mode_str = match self.conf.mode {
            rtftp::Mode::OCTET => "octet",
            rtftp::Mode::NETASCII => "netascii",
        };
        self.tftp.append_option(&mut buf, filename, mode_str);
        self.append_option_req(&mut buf, size);

        buf
    }

    fn handle_wrq(&mut self, sock: &UdpSocket) -> Result<String, io::Error> {
        let mut file = File::open(self.conf.filename.as_path())?;
        let err_invalidpath = || io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename");

        let filename = self.conf.filename.file_name().ok_or_else(err_invalidpath)?
                                         .to_str().ok_or_else(err_invalidpath)?;
        let metadata = file.metadata().map_err(|_| err_invalidpath())?;
        if !metadata.is_file() {
            return Err(err_invalidpath());
        }

        let tsize = self.tftp.transfersize(&mut file)?;
        let buf = self.init_req(rtftp::Opcode::WRQ, filename, tsize);

        let mut remote = None;
        for _ in 1..3 {
            sock.send_to(&buf, self.conf.remote)?;
            remote = self.wait_for_option_ack(sock);
            if remote.is_none() {
                /* for WRQ either OACK or ACK is replied */
                remote = self.wait_for_response(sock, rtftp::Opcode::ACK, 0, None)?;
            }
            if remote.is_some() {
                break;
            }
        }
        /* reconnect to remote to communicate from now on with updated port */
        match remote {
            Some(r) => sock.connect(r).expect("connecting to remote failed"),
            None => return Err(io::Error::new(io::ErrorKind::TimedOut, "No response from server")),
        }

        match self.tftp.send_file(sock, &mut file) {
            Ok(_) => Ok(format!("Sent {} to {}.", self.conf.filename.display(), self.conf.remote)),
            Err(err) => {
                let error = format!("Sending {} to {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
                self.tftp.send_error(sock, 0, "Sending error")?;
                Err(io::Error::new(err.kind(), error))
            }
        }
    }

    fn handle_rrq(&mut self, sock: &UdpSocket) -> Result<String, io::Error> {
        let err_invalidpath = || io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename");
        let filename = self.conf.filename.file_name().ok_or_else(err_invalidpath)?;
        let outpath = env::current_dir().expect("Can't get current directory").join(filename);
        let mut file = File::create(outpath)?;
        let filename = self.conf.filename.to_str().ok_or_else(err_invalidpath)?;

        let buf = self.init_req(rtftp::Opcode::RRQ, filename, 0);

        let mut remote = None;
        for _ in 1..3 {
            sock.send_to(&buf, self.conf.remote)?;
            let oack_remote = self.wait_for_option_ack(sock);
            if let Some(r) = oack_remote {
                /* for RRQ the received OACKs need to be acked */
                self.tftp.send_ack_to(sock, r, 0)?;
            }
            remote = self.wait_for_response(sock, rtftp::Opcode::DATA, 1, oack_remote)?;
            if remote.is_some() {
                break;
            }
        }
        /* reconnect to remote to communicate from now on with updated port */
        match remote {
            Some(r) => sock.connect(r).expect("connecting to remote failed"),
            None => return Err(io::Error::new(io::ErrorKind::TimedOut, "No response from server")),
        }

        match self.tftp.recv_file(sock, &mut file) {
            Ok(_) => Ok(format!("Received {} from {}.", self.conf.filename.display(), self.conf.remote)),
            Err(err) => {
                let error = format!("Receiving {} from {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
                self.tftp.send_error(sock, 0, "Receiving error")?;
                Err(std::io::Error::new(err.kind(), error))
            }
        }
    }

    pub fn start(&mut self) {
        self.tftp.set_progress_callback(update_progress);
        let socket = UdpSocket::bind("[::]:0").expect("binding failed");
        socket.set_read_timeout(Some(Duration::from_secs(5))).expect("setting socket timeout failed");

        let err = match self.conf.operation {
            Operation::RRQ => self.handle_rrq(&socket),
            Operation::WRQ => self.handle_wrq(&socket),
        };
        match err {
            Ok(msg) => println!("{}", msg),
            Err(err) => println!("Error: {}", err),
        }
    }
}

fn usage(opts: &Options, program: &str, error: Option<String>) {
    if let Some(err) = error {
        println!("{}\n", err);
    }
    let version = rtftp::VERSION.unwrap_or("");
    println!("{}", opts.usage(format!("RusTFTP {}\n\n{} [options] <remote>[:port]", version, program).as_str()));
}

fn parse_commandline(args: &[String]) -> Option<Configuration> {
    let program = args[0].clone();
    let mut operation = None;
    let mut mode = rtftp::Mode::OCTET;
    let mut filename = None;
    let mut blksize = 1428;

    let mut opts = Options::new();
    opts.optflag("h", "help", "display usage information");
    opts.optopt("g", "get", "download file from remote server", "FILE");
    opts.optopt("p", "put", "upload file to remote server", "FILE");
    opts.optopt("b", "blksize", format!("negotiate a different block size (default: {})", blksize).as_ref(), "SIZE");
    opts.optflag("n", "netascii","use netascii mode (instead of octet)");

    let getopts_fail = |err: getopts::Fail| { usage(&opts, &program, Some(err.to_string())) };
    let conv_error = |err: std::num::ParseIntError| { usage(&opts, &program, Some(err.to_string())) };

    let matches = opts.parse(&args[1..]).map_err(getopts_fail).ok()?;
    if matches.opt_present("h") || matches.free.len() != 1 {
        usage(&opts, &program, None);
        return None;
    }

    if let Some(f) = matches.opt_str("g") {
        operation = Some(Operation::RRQ);
        filename = Some(Path::new(&f).to_path_buf());
    }
    if let Some(f) = matches.opt_str("p") {
        operation = Some(Operation::WRQ);
        filename = Some(Path::new(&f).to_path_buf());
    }

    if operation.is_none() || (matches.opt_present("g") && matches.opt_present("p")) {
        usage(&opts, &program, Some("Exactly one of g (get) and p (put) required".to_string()));
        return None;
    }

    if matches.opt_present("n") {
        mode = rtftp::Mode::NETASCII;
    }

    let remote_in = matches.free[0].as_str();
    let remote = match remote_in.to_socket_addrs() {
        Ok(i) => i,
        Err(_) => match (remote_in, 69).to_socket_addrs() {
            Ok(j) => j,
            Err(_) => {
                usage(&opts, &program, Some("Failed to parse and lookup specified remote".to_string()));
                return None;
            }
        },
    }.next();

    blksize = matches.opt_get_default::<usize>("b", blksize).map_err(conv_error).ok()?;

    Some(Configuration {
        operation: operation.unwrap(),
        mode,
        filename: filename.unwrap(),
        remote: remote.unwrap(),
        blksize,
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let conf = match parse_commandline(&args) {
        Some(c) => c,
        None => return,
    };

    Tftpc::new(conf).start();
}
