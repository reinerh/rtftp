/*
 * Copyright 2019 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

extern crate getopts;
use getopts::Options;

extern crate rtftp;

enum Mode {
    RRQ,
    WRQ,
}

struct Configuration {
    mode: Mode,
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
    if current == total {
        print!("\r");
    }
    current
}

impl Tftpc {
    pub fn new(conf: Configuration) -> Tftpc {
        Tftpc {
            tftp: rtftp::Tftp::new(),
            conf,
        }
    }

    fn wait_for_option_ack(&mut self, sock: &UdpSocket) -> Option<SocketAddr> {
        let mut buf = [0; 512];
        match sock.peek_from(&mut buf) {
            Ok(_) => (),
            Err(_) => return None,
        };
        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        if opcode != rtftp::Opcodes::OACK as u16 {
            return None;
        }

        let (len, remote) = match sock.recv_from(&mut buf) {
            Ok(args) => args,
            Err(_) => return None,
        };

        let mut options = self.tftp.parse_options(&buf[2..len]);
        match self.tftp.init_tftp_options(&sock, &mut options) {
            Ok(_) => {}
            Err(_) => return None,
        }

        Some(remote)
    }

    fn wait_for_response(&self, sock: &UdpSocket, expected_opcode: rtftp::Opcodes, expected_block: u16, expected_remote: Option<SocketAddr>) -> Result<Option<SocketAddr>, std::io::Error> {
        let mut buf = [0; 4];
        let (len, remote) = match sock.peek_from(&mut buf) {
            Ok(args) => args,
            Err(err) => return Err(err),
        };

        if let Some(rem) = expected_remote {
            /* verify we got a response from the same client that sent
               an optional previous option ack */
            if rem != remote {
                return Ok(None);
            }
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

        if opcode == rtftp::Opcodes::ERROR as u16 {
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

    fn handle_wrq(&mut self, sock: &UdpSocket) -> Result<String, io::Error> {
        let mut file = match File::open(self.conf.filename.as_path()) {
            Ok(f) => f,
            Err(err) => return Err(err),
        };
        let err_invalidpath = io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename");
        let filename = match self.conf.filename.file_name() {
            Some(f) => match f.to_str() {
                Some(s) => s,
                None => return Err(err_invalidpath),
            },
            None => return Err(err_invalidpath),
        };
        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Err(err_invalidpath),
        };
        if !metadata.is_file() {
            return Err(err_invalidpath);
        }

        let mut buf = Vec::with_capacity(512);
        buf.extend((rtftp::Opcodes::WRQ as u16).to_be_bytes().iter());
        self.tftp.append_option(&mut buf, filename, "octet");
        self.append_option_req(&mut buf, metadata.len());

        let mut remote = None;
        for _ in 1..3 {
            sock.send_to(&buf, self.conf.remote)?;
            remote = self.wait_for_option_ack(&sock);
            if remote.is_none() {
                /* for WRQ either OACK or ACK is replied */
                remote = self.wait_for_response(&sock, rtftp::Opcodes::ACK, 0, None)?;
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

        match self.tftp.send_file(&sock, &mut file) {
            Ok(_) => Ok(format!("Sent {} to {}.", self.conf.filename.display(), self.conf.remote)),
            Err(err) => {
                let error = format!("Sending {} to {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
                self.tftp.send_error(&sock, 0, "Sending error")?;
                Err(io::Error::new(err.kind(), error))
            }
        }
    }

    fn handle_rrq(&mut self, sock: &UdpSocket) -> Result<String, io::Error> {
        let filename = match self.conf.filename.file_name() {
            Some(f) => f,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename")),
        };
        let outpath = env::current_dir().expect("Can't get current directory").join(filename);
        let mut file = match File::create(outpath) {
            Ok(f) => f,
            Err(err) => return Err(err),
        };
        let filename = match self.conf.filename.to_str() {
            Some(f) => f,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename")),
        };

        let mut buf = Vec::with_capacity(512);
        buf.extend((rtftp::Opcodes::RRQ as u16).to_be_bytes().iter());
        self.tftp.append_option(&mut buf, filename, "octet");
        self.append_option_req(&mut buf, 0);

        let mut remote = None;
        for _ in 1..3 {
            sock.send_to(&buf, self.conf.remote)?;
            let oack_remote = self.wait_for_option_ack(&sock);
            if let Some(r) = oack_remote {
                /* for RRQ the received OACKs need to be acked */
                self.tftp.send_ack_to(&sock, r, 0)?;
            }
            remote = self.wait_for_response(&sock, rtftp::Opcodes::DATA, 1, oack_remote)?;
            if remote.is_some() {
                break;
            }
        }
        /* reconnect to remote to communicate from now on with updated port */
        match remote {
            Some(r) => sock.connect(r).expect("connecting to remote failed"),
            None => return Err(io::Error::new(io::ErrorKind::TimedOut, "No response from server")),
        }

        match self.tftp.recv_file(&sock, &mut file) {
            Ok(_) => Ok(format!("Received {} from {}.", self.conf.filename.display(), self.conf.remote)),
            Err(err) => {
                let error = format!("Receiving {} from {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
                self.tftp.send_error(&sock, 0, "Receiving error")?;
                Err(std::io::Error::new(err.kind(), error))
            }
        }
    }

    pub fn start(&mut self) {
        self.tftp.set_progress_callback(update_progress);
        let socket = UdpSocket::bind("[::]:0").expect("binding failed");
        socket.set_read_timeout(Some(Duration::from_secs(5))).expect("setting socket timeout failed");

        let err = match self.conf.mode {
            Mode::RRQ => self.handle_rrq(&socket),
            Mode::WRQ => self.handle_wrq(&socket),
        };
        match err {
            Ok(msg) => println!("{}", msg),
            Err(err) => {
                println!("Error: {}", err);
                return;
            }
        }
    }
}

fn usage(opts: Options, program: String, error: Option<String>) {
    if let Some(err) = error {
        println!("{}\n", err);
    }
    let version = rtftp::VERSION.unwrap_or("");
    println!("{}", opts.usage(format!("RusTFTP {}\n\n{} [options] <remote>[:port]", version, program).as_str()));
}

fn parse_commandline(args: &[String]) -> Result<Configuration, &str> {
    let program = args[0].clone();
    let mut mode = None;
    let mut filename = None;
    let mut blksize = 1428;

    let mut opts = Options::new();
    opts.optflag("h", "help", "display usage information");
    opts.optopt("g", "get", "download file from remote server", "FILE");
    opts.optopt("p", "put", "upload file to remote server", "FILE");
    opts.optopt("b", "blksize", format!("negotiate a different block size (default: {})", blksize).as_ref(), "SIZE");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            usage(opts, program, Some(err.to_string()));
            return Err("Parsing error");
        }
    };
    if matches.opt_present("h") || matches.free.len() != 1 {
        usage(opts, program, None);
        return Err("usage");
    }

    if let Some(f) = matches.opt_str("g") {
        mode = Some(Mode::RRQ);
        filename = Some(Path::new(&f).to_path_buf());
    }
    if let Some(f) = matches.opt_str("p") {
        mode = Some(Mode::WRQ);
        filename = Some(Path::new(&f).to_path_buf());
    }

    if mode.is_none() || (matches.opt_present("g") && matches.opt_present("p")) {
        usage(opts, program, Some("Exactly one of g (get) and p (put) required".to_string()));
        return Err("get put");
    }

    let remote_in = matches.free[0].as_str();
    let remote = match remote_in.to_socket_addrs() {
        Ok(mut i) => i.next(),
        Err(_) => match (remote_in, 69).to_socket_addrs() {
            Ok(mut j) => j.next(),
            Err(_) => {
                usage(opts, program, Some("Failed to parse and lookup specified remote".to_string()));
                return Err("lookup");
            }
        },
    };

    blksize = match matches.opt_get_default::<usize>("b", blksize) {
        Ok(b) => b,
        Err(err) => {
            usage(opts, program, Some(err.to_string()));
            return Err("blksize");
        }
    };

    Ok(Configuration {
        mode: mode.unwrap(),
        filename: filename.unwrap(),
        remote: remote.unwrap(),
        blksize,
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let conf = match parse_commandline(&args) {
        Ok(c) => c,
        Err(_) => return,
    };

    Tftpc::new(conf).start();
}
