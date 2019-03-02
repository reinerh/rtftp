/*
 * Copyright 2019 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::net::{SocketAddr,UdpSocket,ToSocketAddrs};
use std::fs::File;
use std::path::{Path,PathBuf};
use std::env;
use std::io;
use std::time::Duration;
use std::os::unix::ffi::OsStrExt; /* for converting filename into bytes */

extern crate getopts;
use getopts::Options;

mod tftp;

enum Mode {
    RRQ,
    WRQ,
}

struct Configuration {
    mode: Mode,
    filename: PathBuf,
    remote: SocketAddr,
}

struct Tftpc {
    tftp: tftp::Tftp,
    conf: Configuration,
}

impl Tftpc {
    pub fn new(conf: Configuration) -> Tftpc {
        Tftpc {
            tftp: tftp::Tftp::new(),
            conf: conf,
        }
    }

    fn wait_for_response(&self, sock: &UdpSocket, expected_opcode: u16, expected_block: u16) -> Option<SocketAddr> {
        let mut buf = [0; 4];
        let (len, remote) = match sock.peek_from(&mut buf) {
            Ok(args) => args,
            Err(_) => return None,
        };

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

        /* first data packet is expected to be block 1 */
        if len != 4 || opcode != expected_opcode || block_nr != expected_block {
            return None;
        }

        Some(remote)
    }

    fn handle_wrq(&self, sock: &UdpSocket) -> Result<(), io::Error> {
        let mut file = match File::open(self.conf.filename.as_path()) {
            Ok(f) => f,
            Err(err) => return Err(err),
        };
        let filename = match self.conf.filename.file_name() {
            Some(f) => f,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename")),
        };

        let mut buf = Vec::with_capacity(512);
        buf.extend([0x00, 0x02].iter());
        buf.extend(filename.as_bytes());
        buf.push(0x00);
        buf.extend("octet".bytes());
        buf.push(0x00);

        let mut remote = None;
        for _ in 1 .. 3 {
            sock.send_to(&buf, self.conf.remote)?;
            remote = self.wait_for_response(&sock, 4, 0);
            if let Some(_) = remote {
                break;
            }
        }
        /* reconnect to remote to communicate from now on with updated port */
        match remote {
            Some(r) => sock.connect(r).expect("connecting to remote failed"),
            None => return Err(io::Error::new(io::ErrorKind::TimedOut, "No response from server")),
        }

        match self.tftp.send_file(&sock, &mut file) {
            Ok(_) => println!("Sent {} to {}.", self.conf.filename.display(), self.conf.remote),
            Err(err) => {
                self.tftp.send_error(&sock, 0, "Sending error")?;
                println!("Sending {} to {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
            },
        }

        Ok(())
    }

    fn handle_rrq(&self, sock: &UdpSocket) -> Result<(), io::Error> {
        let filename = match self.conf.filename.file_name() {
            Some(f) => f,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid path/filename")),
        };
        let outpath = env::current_dir().expect("Can't get current directory").join(filename);
        let mut file = match File::create(outpath) {
            Ok(f) => f,
            Err(err) => return Err(err),
        };

        let mut buf = Vec::with_capacity(512);
        buf.extend([0x00, 0x01].iter());
        buf.extend(self.conf.filename.as_os_str().as_bytes());
        buf.push(0x00);
        buf.extend("octet".bytes());
        buf.push(0x00);

        let mut remote = None;
        for _ in 1 .. 3 {
            sock.send_to(&buf, self.conf.remote)?;
            remote = self.wait_for_response(&sock, 3, 1);
            if let Some(_) = remote {
                break;
            }
        }
        /* reconnect to remote to communicate from now on with updated port */
        match remote {
            Some(r) => sock.connect(r).expect("connecting to remote failed"),
            None => return Err(io::Error::new(io::ErrorKind::TimedOut, "No response from server")),
        }

        match self.tftp.recv_file(&sock, &mut file) {
            Ok(_) => println!("Received {} from {}.", self.conf.filename.display(), self.conf.remote),
            Err(err) => {
                self.tftp.send_error(&sock, 0, "Receiving error")?;
                println!("Receiving {} from {} failed ({}).", self.conf.filename.display(), self.conf.remote, err);
            },
        }

        Ok(())
    }

    pub fn start(&self) {
        let socket = UdpSocket::bind("[::]:0").expect("binding failed");
        socket.set_read_timeout(Some(Duration::from_secs(5))).expect("setting socket timeout failed");
        //socket.connect(self.conf.remote).expect("conneting to remote failed");

        let err = match self.conf.mode {
            Mode::RRQ => self.handle_rrq(&socket),
            Mode::WRQ => self.handle_wrq(&socket),
        };
        match err {
            Ok(_) => {},
            Err(err) => {
                println!("Error: {}", err);
                return;
            }
        }
    }
}

fn usage(opts: Options, program: String, error: Option<String>) {
    match error {
        None => {},
        Some(err) => println!("{}\n", err),
    }
    println!("{}", opts.usage(format!("RusTFTP\n\n{} [options] <remote>[:port]", program).as_str()));
}

fn parse_commandline<'a>(args: &'a Vec<String>) -> Result<Configuration, &'a str> {
    let program = args[0].clone();
    let mut mode = None;
    let mut filename = None;

    let mut opts = Options::new();
    opts.optflag("h", "help", "display usage information");
    opts.optopt("g", "get", "download file from remote server", "FILE");
    opts.optopt("p", "put", "upload file to remote server", "FILE");
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

    match matches.opt_str("g") {
        Some(f) => {
            mode = Some(Mode::RRQ);
            filename = Some(Path::new(&f).to_path_buf());
        }
        None => ()
    }
    match matches.opt_str("p") {
        Some(f) => {
            mode = Some(Mode::WRQ);
            filename = Some(Path::new(&f).to_path_buf());
        }
        None => ()
    }

    if mode.is_none() || (matches.opt_present("g") && matches.opt_present("p")) {
        usage(opts, program, Some("Exactly one of g (get) and p (put) required".to_string()));
        return Err("get put");
    }

    let remote_in = matches.free[0].as_str();
    let remote = match remote_in.to_socket_addrs() {
        Ok(mut i) => i.next(),
        Err(_) => {
            match (remote_in, 69).to_socket_addrs() {
                Ok(mut j) => j.next(),
                Err(_) => {
                    usage(opts, program, Some("Failed to parse and lookup specified remote".to_string()));
                    return Err("lookup");
                },
            }
        }
    };

    Ok(Configuration{
        mode: mode.unwrap(),
        filename: filename.unwrap(),
        remote: remote.unwrap(),
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
