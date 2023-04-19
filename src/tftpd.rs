/*
 * Copyright 2019-2022 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::env;
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::unistd::{chroot, setresgid, setresuid, Gid, Uid, ROOT};
use getopts::Options;
use threadpool::ThreadPool;

#[cfg(feature = "landlock")]
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, RestrictionStatus, RulesetAttr,
    RulesetCreatedAttr, RulesetError, RulesetStatus, ABI
};

#[derive(Clone)]
struct Configuration {
    port: u16,
    uid: u32,
    gid: u32,
    ro: bool,
    wo: bool,
    threads: usize,
    dir: PathBuf,
}

impl Default for Configuration {
    fn default() -> Configuration {
        Configuration {
            port: 69,
            uid: 65534,
            gid: 65534,
            ro: false,
            wo: false,
            threads: 2,
            dir: env::current_dir().expect("Can't get current directory"),
        }
    }
}

#[derive(Clone)]
struct Tftpd {
    tftp: rtftp::Tftp,
    conf: Configuration,
}

impl Tftpd {
    pub fn new(conf: Configuration) -> Tftpd {
        Tftpd {
            tftp: rtftp::Tftp::new(),
            conf,
        }
    }

    fn file_allowed(&self, filename: &Path) -> Option<PathBuf> {
        if self.conf.dir == PathBuf::from("/") {
            /* running either chrooted in requested directory,
               or whole root is being served */
            return Some(filename.to_path_buf());
        }

        /* get parent to check dir where file should be read/written */
        let path = self.conf.dir.join(filename)
                                .parent()?
                                .canonicalize()
                                .ok()?;

        /* check last component of given filename appended to canonicalized path */
        match path.join(filename.file_name()?).strip_prefix(&self.conf.dir) {
            Ok(p) if p != PathBuf::new() => Some(p.to_path_buf()),
            _ => None,
        }
    }

    fn handle_wrq(&mut self, socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<String, io::Error> {
        let (filename, mode, mut options) = self.tftp.parse_file_mode_options(buf)?;
        self.tftp.init_tftp_options(socket, &mut options)?;

        match mode.as_ref() {
            "octet" => self.tftp.set_mode(rtftp::Mode::OCTET),
            "netascii" => self.tftp.set_mode(rtftp::Mode::NETASCII),
            _ => {
                self.tftp.send_error(socket, 0, "Unsupported mode")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
            }
        }

        let path = match self.file_allowed(&filename) {
            Some(p) => p,
            None => {
                let err = format!("Receiving {} from {} failed (permission check failed).", filename.display(), cl);
                self.tftp.send_error(socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, err));
            }
        };

        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => {
                let error = format!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(socket, 6, "File already exists")?;
                return Err(io::Error::new(err.kind(), error));
            }
            Err(err) => {
                let error = format!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(socket, 6, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, error));
            }
        };

        self.tftp.ack_options(socket, &options, false)?;
        match self.tftp.recv_file(socket, &mut file) {
            Ok(_) => Ok(format!("Received {} from {}.", path.display(), cl)),
            Err(ref err) => {
                let error = format!("Receiving {} from {} failed ({}).", path.display(), cl, err);
                self.tftp.send_error(socket, 0, "Receiving error")?;
                Err(io::Error::new(err.kind(), error))
            }
        }
    }

    fn handle_rrq(&mut self, socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<String, io::Error> {
        let (filename, mode, mut options) = self.tftp.parse_file_mode_options(buf)?;
        self.tftp.init_tftp_options(socket, &mut options)?;

        match mode.as_ref() {
            "octet" => self.tftp.set_mode(rtftp::Mode::OCTET),
            "netascii" => self.tftp.set_mode(rtftp::Mode::NETASCII),
            _ => {
                self.tftp.send_error(socket, 0, "Unsupported mode")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
            }
        }

        let path = match self.file_allowed(&filename) {
            Some(p) => p,
            None => {
                let err = format!("Sending {} to {} failed (permission check failed).", filename.display(), cl);
                self.tftp.send_error(socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, err));
            }
        };

        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
                let err = format!("Sending {} to {} failed ({}).", path.display(), cl, error);
                self.tftp.send_error(socket, 1, "File not found")?;
                return Err(io::Error::new(io::ErrorKind::NotFound, err));
            }
            Err(error) => {
                let err = format!("Sending {} to {} failed ({}).", path.display(), cl, error);
                self.tftp.send_error(socket, 2, "Permission denied")?;
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, err));
            }
        };
        if !file.metadata()?.is_file() {
            self.tftp.send_error(socket, 1, "File not found")?;
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        }

        if let Some(opt) = options.get_mut("tsize") {
            *opt = self.tftp.transfersize(&mut file)?.to_string();
        }
        self.tftp.ack_options(socket, &options, true)?;
        match self.tftp.send_file(socket, &mut file) {
            Ok(_) => Ok(format!("Sent {} to {}.", path.display(), cl)),
            Err(err) => {
                let error = format!("Sending {} to {} failed ({}).", path.display(), cl, err);
                Err(std::io::Error::new(err.kind(), error))
            }
        }
    }

    pub fn handle_client(&mut self, cl: &SocketAddr, buf: &[u8]) -> Result<String, io::Error> {
        let socket = UdpSocket::bind("[::]:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.connect(cl)?;

        if buf.len() < 2 {
            self.tftp.send_error(&socket, 0, "Invalid request length")?;
            return Err(io::Error::new(io::ErrorKind::Other, "invalid request length"));
        }

        match u16::from_be_bytes([buf[0], buf[1]]) {  // opcode
            o if o == rtftp::Opcode::RRQ as u16 => {
                if self.conf.wo {
                    self.tftp.send_error(&socket, 4, "reading not allowed")?;
                    Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"))
                } else {
                    self.handle_rrq(&socket, cl, &buf[2..])
                }
            }
            o if o == rtftp::Opcode::WRQ as u16 => {
                if self.conf.ro {
                    self.tftp.send_error(&socket, 4, "writing not allowed")?;
                    Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"))
                } else {
                    self.handle_wrq(&socket, cl, &buf[2..])
                }
            }
            o if o == rtftp::Opcode::ERROR as u16 => Ok(format!("Received ERROR from {}", cl)),
            _ => {
                self.tftp.send_error(&socket, 4, "Unexpected opcode")?;
                Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode"))
            }
        }
    }

    fn drop_privs(&self, uid: u32, gid: u32) -> Result<(), Box<dyn Error>> {
        let root_uid = ROOT;
        let root_gid = Gid::from_raw(0);
        let unpriv_uid = Uid::from_raw(uid);
        let unpriv_gid = Gid::from_raw(gid);

        if Gid::current() != root_gid
            && Gid::effective() != root_gid
            && Uid::current() != root_uid
            && Uid::effective() != root_uid
        {
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

    fn chroot_destdir(&mut self) -> Result<(), nix::Error> {
        /* chroot will only succeed if we have required permissions;
           either running as root or having CAP_SYS_CHROOT.
           propagate error only if chroot should have succeeded. */
        match chroot(&self.conf.dir) {
            Ok(_) => {
                /* configured dir is now new root directory */
                self.conf.dir = PathBuf::from("/");
                Ok(())
            },
            Err(err) if err == nix::errno::Errno::EPERM => Ok(()),
            Err(err) if Uid::effective() == ROOT => Err(err),
            Err(_) => Ok(()),
        }
    }

    #[cfg(feature = "landlock")]
    fn restrict_filesystem(&self) {
        let abi = ABI::V1;
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);
        let access_write = AccessFs::from_write(abi);

        let pathfd = PathFd::new(&self.conf.dir).expect("Directory can't be opened");

        let access = if self.conf.ro {
            access_read
        } else if self.conf.wo {
            access_write
        } else {
            access_all
        };

        let restrict = || -> Result<RestrictionStatus, RulesetError> {
            landlock::Ruleset::new()
                    .handle_access(access_all)?
                    .create()?
                    .add_rule(PathBeneath::new(pathfd, access))?
                    .restrict_self()
        };

        let status = restrict().expect("Setting up landlock restriction failed");
        if status.ruleset != RulesetStatus::FullyEnforced {
            eprintln!("Landlock restrictions not (fully) applied (maybe kernel too old?).");
        }
    }

    pub fn start(&mut self) {
        let socket = match UdpSocket::bind(format!("[::]:{}", self.conf.port)) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("Binding a socket failed: {}", err);
                return;
            }
        };

        #[cfg(feature = "landlock")]
        self.restrict_filesystem();

        match self.chroot_destdir() {
            Ok(_) => {},
            Err(err) => {
                eprintln!("Changing root directory failed ({}).", err);
                return;
            }
        }
        match self.drop_privs(self.conf.uid, self.conf.gid) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Dropping privileges failed: {}", err);
                return;
            }
        };

        match env::set_current_dir(&self.conf.dir) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Changing directory failed ({}).", err);
                return;
            }
        }

        let pool = ThreadPool::new(self.conf.threads);
        loop {
            let mut buf = [0; 2048];
            let (n, src) = match socket.recv_from(&mut buf) {
                Ok(args) => args,
                Err(err) => {
                    eprintln!("Receiving data from socket failed: {}", err);
                    break;
                }
            };

            let mut worker = self.clone();
            pool.execute(move || {
                match worker.handle_client(&src, &buf[0..n]) {
                    Ok(msg) => println!("{}", msg),
                    Err(err) => println!("{}", err),
                }
            });
        }
    }
}

fn usage(opts: &Options, program: &str, error: Option<String>) {
    if let Some(err) = error {
        println!("{}\n", err);
    }
    let version = rtftp::VERSION.unwrap_or("");
    println!("{}", opts.usage(format!("RusTFTP {}\n\n{} [options] [directory]", version, program).as_str()));
}

fn parse_commandline(args: &[String]) -> Option<Configuration> {
    let program = args[0].clone();
    let mut conf: Configuration = Default::default();
    let mut opts = Options::new();
    opts.optflag("h", "help", "display usage information");
    opts.optopt("p", "port", format!("port to listen on (default: {})", conf.port).as_ref(), "PORT");
    opts.optopt("u", "uid", format!("user id to run as (default: {})", conf.uid).as_ref(), "UID");
    opts.optopt("g", "gid", format!("group id to run as (default: {})", conf.gid).as_ref(), "GID");
    opts.optflag("r", "read-only", "allow only reading/downloading of files (RRQ)");
    opts.optflag("w", "write-only", "allow only writing/uploading of files (WRQ)");
    opts.optopt("t", "threads", format!("number of worker threads (default: {})", conf.threads).as_ref(), "N");

    let getopts_fail = |err: getopts::Fail| { usage(&opts, &program, Some(err.to_string())) };
    let conv_error = |err: std::num::ParseIntError| { usage(&opts, &program, Some(err.to_string())) };

    let matches = opts.parse(&args[1..]).map_err(getopts_fail).ok()?;
    if matches.opt_present("h") {
        usage(&opts, &program, None);
        return None;
    }

    conf.port = matches.opt_get_default("p", conf.port).map_err(conv_error).ok()?;
    conf.uid = matches.opt_get_default("u", conf.uid).map_err(conv_error).ok()?;
    conf.gid = matches.opt_get_default("g", conf.gid).map_err(conv_error).ok()?;
    conf.threads = matches.opt_get_default("t", conf.threads).map_err(conv_error).ok()?;
    conf.ro = matches.opt_present("r");
    conf.wo = matches.opt_present("w");
    if conf.ro && conf.wo {
        usage(&opts, &program, Some(String::from("Only one of r (read-only) and w (write-only) allowed")));
        return None;
    }
    if !matches.free.is_empty() {
        conf.dir = Path::new(&matches.free[0]).to_path_buf();
    }

    Some(conf)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let conf = match parse_commandline(&args) {
        Some(c) => c,
        None => return,
    };

    Tftpd::new(conf).start();
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file_allowed() {
        let conf: Configuration = Default::default();
        let tftpd = Tftpd::new(conf);

        /* allowed */
        assert!(tftpd.file_allowed(Path::new("testfile")).is_some());
        assert!(tftpd.file_allowed(&tftpd.conf.dir.join(Path::new("testfile"))).is_some());

        /* forbidden */
        assert!(tftpd.file_allowed(Path::new("nonexisting_dir/testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("/nonexisting_dir/testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("../testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("testfile/../")).is_none());
        assert!(tftpd.file_allowed(Path::new("testfile/../testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("/root/testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("/testfile")).is_none());
        assert!(tftpd.file_allowed(Path::new("/dev/null")).is_none());
        assert!(tftpd.file_allowed(Path::new("../../../../../../../../../../../../../etc/motd")).is_none());
        assert!(tftpd.file_allowed(Path::new("")).is_none());
        assert!(tftpd.file_allowed(Path::new("./")).is_none());
        assert!(tftpd.file_allowed(&tftpd.conf.dir).is_none());
    }
}
