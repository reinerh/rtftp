/*
 * Copyright 2019 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::net::{SocketAddr,UdpSocket};
use std::fs::OpenOptions;
use std::fs::File;
use std::path::{Path,PathBuf};
use std::error::Error;
use std::env;
use std::io;
use std::time::Duration;

extern crate nix;
use nix::unistd::{Gid,Uid,setresgid,setresuid};

extern crate getopts;
use getopts::Options;

mod tftp;

struct Configuration {
    port: u16,
    uid: u32,
    gid: u32,
    ro: bool,
    wo: bool,
    dir: PathBuf,
}

struct Tftpd {
    tftp: tftp::Tftp,
    conf: Configuration,
}

impl Tftpd {
    pub fn new(conf: Configuration) -> Tftpd {
        Tftpd{
            tftp: tftp::Tftp::new(),
            conf: conf,
        }
    }

    fn file_allowed(&self, filename: &Path) -> Option<PathBuf> {
        /* get parent to check dir where file should be read/written */
        let path = Path::new(".").join(filename);
        let path = match path.parent() {
            Some(p) => p,
            None => return None,
        };
        let path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => return None,
        };

        /* get last component to append to canonicalized path */
        let filename = match filename.file_name() {
            Some(f) => f,
            None => return None,
        };
        let path = path.join(filename);

        let cwd = match env::current_dir() {
            Ok(p) => p,
            Err(_) => return None,
        };

        match path.strip_prefix(cwd) {
            Ok(p) => Some(p.to_path_buf()),
            Err(_) => return None,
        }
    }


    fn handle_wrq(&mut self, socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
        let (filename, mode, mut options) = self.tftp.parse_file_mode_options(buf)?;
        self.tftp.init_tftp_options(&socket, &mut options, false)?;

        match mode.as_ref() {
            "octet" => (),
            _ => {
                self.tftp.send_error(&socket, 0, "Unsupported mode")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
            }
        }

        let path = match self.file_allowed(&filename) {
            Some(p) => p,
            None => {
                println!("Sending {} to {} failed (permission check failed).", filename.display(), cl);
                self.tftp.send_error(&socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
            }
        };

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => {
                println!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(&socket, 6, "File already exists")?;
                return Err(io::Error::new(err.kind(), "already exists"));
            },
            Err(err) => {
                println!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(&socket, 6, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
            }
        };

        match self.tftp.recv_file(&socket, &mut file) {
            Ok(_) => println!("Received {} from {}.", path.display(), cl),
            Err(ref err) => {
                println!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(&socket, 0, "Receiving error")?;
                return Err(io::Error::new(err.kind(), err.to_string()));
            }
        }
        Ok(())
    }

    fn handle_rrq(&mut self, socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
        let (filename, mode, mut options) = self.tftp.parse_file_mode_options(buf)?;
        self.tftp.init_tftp_options(&socket, &mut options, true)?;

        match mode.as_ref() {
            "octet" => (),
            _ => {
                self.tftp.send_error(&socket, 0, "Unsupported mode")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
            }
        }

        let path = match self.file_allowed(&filename) {
            Some(p) => p,
            None => {
                println!("Sending {} to {} failed (permission check failed).", filename.display(), cl);
                self.tftp.send_error(&socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
            }
        };

        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
                self.tftp.send_error(&socket, 1, "File not found")?;
                return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
            },
            Err(_) => {
                self.tftp.send_error(&socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
            }
        };
        if !file.metadata()?.is_file() {
            self.tftp.send_error(&socket, 1, "File not found")?;
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        }
        match self.tftp.send_file(&socket, &mut file) {
            Ok(_) => println!("Sent {} to {}.", path.display(), cl),
            Err(err) => println!("Sending {} to {} failed ({}).", path.display(), cl, err.to_string()),
        }
        Ok(())
    }

    pub fn handle_client(&mut self, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
        let socket = UdpSocket::bind("[::]:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.connect(cl)?;

        let _opcode = match u16::from_be_bytes([buf[0], buf[1]]) {
            1 /* RRQ */ => {
                if self.conf.wo {
                    self.tftp.send_error(&socket, 4, "reading not allowed")?;
                    return Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"));
                } else {
                    self.handle_rrq(&socket, &cl, &buf[2..])?;
                }
            },
            2 /* WRQ */ => {
                if self.conf.ro {
                    self.tftp.send_error(&socket, 4, "writing not allowed")?;
                    return Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"));
                } else {
                    self.handle_wrq(&socket, &cl, &buf[2..])?;
                }
            },
            5 /* ERROR */ => println!("Received ERROR from {}", cl),
            _ => {
                self.tftp.send_error(&socket, 4, "Unexpected opcode")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode"));
            }
        };
        Ok(())
    }

    fn drop_privs(&self, uid: u32, gid: u32) -> Result<(), Box<Error>> {
        let root_uid = Uid::from_raw(0);
        let root_gid = Gid::from_raw(0);
        let unpriv_uid = Uid::from_raw(uid);
        let unpriv_gid = Gid::from_raw(gid);

        if Gid::current() != root_gid && Gid::effective() != root_gid
            && Uid::current() != root_uid && Uid::effective() != root_uid {
            /* already unprivileged user */
            return Ok(());
        }

        if Gid::current() == root_gid || Gid::effective() == root_gid {
            setresgid(unpriv_gid, unpriv_gid, unpriv_gid)?;
        }

        if Uid::current() == root_uid || Uid::effective() == root_uid {
            setresuid(unpriv_uid, unpriv_uid, unpriv_uid)?;
        }

        Ok(())
    }

    pub fn start(&mut self) {
        let socket = match UdpSocket::bind(format!("[::]:{}", self.conf.port)) {
            Ok(s) => s,
            Err(err) => {
                println!("Binding a socket failed: {}", err);
                return;
            }
        };
        match self.drop_privs(self.conf.uid, self.conf.gid) {
            Ok(_) => (),
            Err(err) => {
                println!("Dropping privileges failed: {}", err);
                return;
            }
        };

        match env::set_current_dir(&self.conf.dir) {
            Ok(_) => (),
            Err(err) => {
                println!("Changing directory to {} failed ({}).", &self.conf.dir.display(), err);
                return;
            }
        }

        loop {
            let mut buf = [0; 2048];
            let (n, src) = match socket.recv_from(&mut buf) {
                Ok(args) => args,
                Err(err) => {
                    println!("Receiving data from socket failed: {}", err);
                    break;
                }
            };

            match self.handle_client(&src, &buf[0..n]) {
                /* errors intentionally ignored */
                _ => (),
            }
        }

    }
}

fn usage(opts: Options, error: Option<String>) {
    match error {
        None => {},
        Some(err) => println!("{}\n", err),
    }
    println!("{}", opts.usage("RusTFTP"));

}

fn parse_commandline<'a>(args: &'a Vec<String>) -> Result<Configuration, &'a str> {
    let mut conf = Configuration{
        port: 69,
        uid: 65534,
        gid: 65534,
        ro: false,
        wo: false,
        dir: env::current_dir().expect("Can't get current directory"),
    };
    let mut opts = Options::new();
    opts.optflag("h", "help", "display usage information");
    opts.optopt("d", "directory", "directory to serve (default: current directory)", "DIRECTORY");
    opts.optopt("p", "port", format!("port to listen on (default: {})", conf.port).as_ref(), "PORT");
    opts.optopt("u", "uid", format!("user id to run as (default: {})", conf.uid).as_ref(), "UID");
    opts.optopt("g", "gid", format!("group id to run as (default: {})", conf.gid).as_ref(), "GID");
    opts.optflag("r", "read-only", "allow only reading/downloading of files (RRQ)");
    opts.optflag("w", "write-only", "allow only writing/uploading of files (WRQ)");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => {
            usage(opts, Some(err.to_string()));
            return Err("Parsing error");
        }
    };
    if matches.opt_present("h") {
        usage(opts, None);
        return Err("usage");
    }

    conf.port = match matches.opt_get_default::<u16>("p", conf.port) {
        Ok(p) => p,
        Err(err) => {
            usage(opts, Some(err.to_string()));
            return Err("port");
        }
    };
    conf.uid = match matches.opt_get_default::<u32>("u", conf.uid) {
        Ok(u) => u,
        Err(err) => {
            usage(opts, Some(err.to_string()));
            return Err("uid");
        }
    };
    conf.gid = match matches.opt_get_default::<u32>("g", conf.gid) {
        Ok(g) => g,
        Err(err) => {
            usage(opts, Some(err.to_string()));
            return Err("gid");
        }
    };
    conf.ro = matches.opt_present("r");
    conf.wo = matches.opt_present("w");
    if conf.ro && conf.wo {
        usage(opts, Some(String::from("Only one of r (read-only) and w (write-only) allowed")));
        return Err("ro and wo");
    }
    if matches.opt_present("d") {
        conf.dir = match matches.opt_str("d") {
            Some(d) => Path::new(&d).to_path_buf(),
            None => {
                usage(opts, None);
                return Err("directory");
            }
        };
    }

    return Ok(conf);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let conf = match parse_commandline(&args) {
        Ok(c) => c,
        Err(_) => return,
    };

    Tftpd::new(conf).start();
}
