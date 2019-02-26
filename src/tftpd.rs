use std::net::{SocketAddr,UdpSocket};
use std::fs::OpenOptions;
use std::fs::File;
use std::path::{Path,PathBuf};
use std::error::Error;
use std::env;
use std::io;
use std::io::prelude::*;
use std::time::Duration;

extern crate nix;
use nix::unistd::{Gid,Uid,setresgid,setresuid};

extern crate getopts;
use getopts::Options;

struct Configuration {
    port: u16,
    uid: u32,
    gid: u32,
    ro: bool,
    wo: bool,
}

fn wait_for_ack(sock: &UdpSocket, expected_block: u16) -> Result<bool, io::Error> {
    let mut buf = [0; 4];
    match sock.recv(&mut buf) {
        Ok(_) => (),
        Err(ref error) if [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&error.kind()) => {
            return Ok(false);
        }
        Err(err) => return Err(err),
    };

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

    if opcode == 4 && block_nr == expected_block {
        return Ok(true)
    }

    Ok(false)
}

fn parse_file_mode(buf: &[u8]) -> Result<(PathBuf, String), io::Error> {
    let mut iter = buf.iter();

    let dataerr = io::Error::new(io::ErrorKind::InvalidData, "invalid data received");

    let fname_len = match iter.position(|&x| x == 0) {
        Some(len) => len,
        None => return Err(dataerr),
    };
    let fname_begin = 0;
    let fname_end = fname_begin + fname_len;
    let filename = match String::from_utf8(buf[fname_begin .. fname_end].to_vec()) {
        Ok(fname) => fname,
        Err(_) => return Err(dataerr),
    };
    let filename = Path::new(&filename);

    let mode_len = match iter.position(|&x| x == 0) {
        Some(len) => len,
        None => return Err(dataerr),
    };
    let mode_begin = fname_end + 1;
    let mode_end = mode_begin + mode_len;
    let mode = match String::from_utf8(buf[mode_begin .. mode_end].to_vec()) {
        Ok(m) => m.to_lowercase(),
        Err(_) => return Err(dataerr),
    };

    Ok((filename.to_path_buf(), mode))
}

fn send_file(socket: &UdpSocket, path: &Path) -> Result<(), io::Error> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
            send_error(&socket, 1, "File not found")?;
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        },
        Err(_) => {
            send_error(&socket, 2, "Permission denied")?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        }
    };
    if !file.metadata()?.is_file() {
        send_error(&socket, 1, "File not found")?;
        return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
    }

    let mut block_nr: u16 = 1;

    loop {
        let mut filebuf = [0; 512];
        let len = file.read(&mut filebuf);
        let len = match len {
            Ok(n) => n,
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue, /* retry */
            Err(err) => {
                send_error(&socket, 0, "File reading error")?;
                return Err(err);
            }
        };

        let mut sendbuf = vec![0x00, 0x03];  // opcode
        sendbuf.extend(block_nr.to_be_bytes().iter());
        sendbuf.extend(filebuf[0..len].iter());

        for _ in 1..5 {
            /* try a couple of times to send data, in case of timeouts
               or re-ack of previous data */
            socket.send(&sendbuf)?;
            match wait_for_ack(&socket, block_nr) {
                Ok(true) => break,
                Ok(false) => continue,
                Err(e) => return Err(e),
            };
        }

        if len < 512 {
            /* this was the last block */
            break;
        }

        /* increment with rollover on overflow */
        block_nr = block_nr.wrapping_add(1);
    }
    Ok(())
}

fn recv_file(sock: &UdpSocket, path: &PathBuf) -> Result<(), io::Error> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => f,
        Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => {
            return Err(io::Error::new(err.kind(), "already exists"));
        },
        Err(_) => return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied")),
    };

    let mut block_nr = 0;

    loop {
        let mut buf = [0; 1024];
        let mut len = 0;

        for _ in 1..5 {
            send_ack(&sock, block_nr)?;
            len = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(ref error) if [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&error.kind()) => {
                    /* re-ack and try to recv again */
                    continue;
                }
                Err(err) => return Err(err),
            };
            break;
        }
        if len > 516 || len < 4 {
            /* max size: 2 + 2 + 512 */
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected size"));
        }

        let _opcode = match u16::from_be_bytes([buf[0], buf[1]]) {
            3 /* DATA */ => (),
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode")),
        };
        let nr = u16::from_be_bytes([buf[2], buf[3]]);
        if nr != block_nr.wrapping_add(1) {
            /* already received or packets were missed, re-acknowledge */
            continue;
        }
        block_nr = nr;

        let databuf = &buf[4..len];
        file.write_all(databuf)?;

        if len < 516 {
            break;
        }
    }

    file.flush()?;

    send_ack(&sock, block_nr)?;

    Ok(())
}

fn file_allowed(filename: &Path) -> Option<PathBuf> {
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

fn handle_wrq(socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {

    let (filename, mode) = parse_file_mode(buf)?;

    match mode.as_ref() {
        "octet" => (),
        _ => {
            send_error(&socket, 0, "Unsupported mode")?;
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
        }
    }

    let path = match file_allowed(&filename) {
        Some(p) => p,
        None => {
            println!("Sending {} to {} failed (permission check failed).", filename.display(), cl);
            send_error(&socket, 2, "Permission denied")?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        }
    };

    match recv_file(&socket, &path) {
        Ok(_) => println!("Received {} from {}.", path.display(), cl),
        Err(ref err) => {
            println!("Receiving {} from {} failed ({}).", path.display(), cl, err.to_string());
            match err.kind() {
                io::ErrorKind::PermissionDenied => send_error(&socket, 2, "Permission denied")?,
                io::ErrorKind::AlreadyExists => send_error(&socket, 6, "File already exists")?,
                _ => send_error(&socket, 0, "Receiving error")?,
            }
            return Err(io::Error::new(err.kind(), err.to_string()));
        }
    }
    Ok(())
}


fn handle_rrq(socket: &UdpSocket, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
    let (filename, mode) = parse_file_mode(buf)?;

    match mode.as_ref() {
        "octet" => (),
        _ => {
            send_error(&socket, 0, "Unsupported mode")?;
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported mode"));
        }
    }

    let path = match file_allowed(&filename) {
        Some(p) => p,
        None => {
            println!("Sending {} to {} failed (permission check failed).", filename.display(), cl);
            send_error(&socket, 2, "Permission denied")?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        }
    };

    match send_file(&socket, &path) {
        Ok(_) => println!("Sent {} to {}.", path.display(), cl),
        Err(err) => println!("Sending {} to {} failed ({}).", path.display(), cl, err.to_string()),
    }
    Ok(())
}

fn send_error(socket: &UdpSocket, code: u16, msg: &str) -> Result<(), io::Error> {
    let mut buf = vec![0x00, 0x05];  // opcode
    buf.extend(code.to_be_bytes().iter());
    buf.extend(msg.as_bytes());

    socket.send(&buf)?;
    Ok(())
}

fn send_ack(sock: &UdpSocket, block_nr: u16) -> Result<(), io::Error> {
    let mut buf = vec![0x00, 0x04];  // opcode
    buf.extend(block_nr.to_be_bytes().iter());

    sock.send(&buf)?;

    Ok(())
}

fn handle_client(conf: &Configuration, cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(cl)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let _opcode = match u16::from_be_bytes([buf[0], buf[1]]) {
        1 /* RRQ */ => {
            if conf.wo {
                send_error(&socket, 4, "reading not allowed")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"));
            } else {
                handle_rrq(&socket, &cl, &buf[2..])?;
            }
        },
        2 /* WRQ */ => {
            if conf.ro {
                send_error(&socket, 4, "writing not allowed")?;
                return Err(io::Error::new(io::ErrorKind::Other, "unallowed mode"));
            } else {
                handle_wrq(&socket, &cl, &buf[2..])?;
            }
        },
        5 /* ERROR */ => println!("Received ERROR from {}", cl),
        _ => {
            send_error(&socket, 4, "Unexpected opcode")?;
            return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode"));
        }
    };
    Ok(())
}

fn drop_privs(uid: u32, gid: u32) -> Result<(), Box<Error>> {
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
        let basedir = match matches.opt_str("d") {
            Some(d) => d,
            None => {
                usage(opts, None);
                return Err("directory");
            }
        };
        match env::set_current_dir(Path::new(&basedir)) {
            Ok(_) => (),
            Err(err) => {
                usage(opts, Some(err.to_string()));
                return Err("changing directory");
            }
        }
    }

    return Ok(conf);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let conf = match parse_commandline(&args) {
        Ok(c) => c,
        Err(_) => return,
    };

    let socket = match UdpSocket::bind(format!("0.0.0.0:{}", conf.port)) {
        Ok(s) => s,
        Err(err) => {
            println!("Binding a socket failed: {}", err);
            return;
        }
    };
    match drop_privs(conf.uid, conf.gid) {
        Ok(_) => (),
        Err(err) => {
            println!("Dropping privileges failed: {}", err);
            return;
        }
    };

    loop {
        let mut buf = [0; 2048];
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(args) => args,
            Err(err) => {
                println!("Receiving data from socket failed: {}", err);
                break;
            }
        };

        match handle_client(&conf, &src, &buf[0..n]) {
            /* errors intentionally ignored */
            _ => (),
        }
    }
}
