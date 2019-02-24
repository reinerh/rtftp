use std::net::{SocketAddr,UdpSocket};
use std::fs::File;
use std::path::Path;
use std::error::Error;
use std::env;
use std::io;
use std::io::prelude::*;

extern crate nix;
use nix::unistd::{Gid,Uid,setresgid,setresuid};

fn handle_wrq(_cl: &SocketAddr, _buf: &[u8]) -> Result<(), io::Error> {
    Ok(())
}

fn wait_for_ack(sock: &UdpSocket, expected_block: u16) -> Result<bool, io::Error> {
    let mut buf = [0; 4];
    sock.recv(&mut buf)?;

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

    if opcode == 4 && block_nr == expected_block {
        return Ok(true)
    }

    Ok(false)
}

fn send_file(cl: &SocketAddr, filename: &str) -> Result<(), io::Error> {
    let file = File::open(filename);
    let mut file = match file {
        Ok(f) => f,
        Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
            handle_error(cl, 1, "File not found")?;
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        },
        Err(_) => {
            handle_error(cl, 2, "Permission denied")?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        }
    };
    if !file.metadata()?.is_file() {
        handle_error(cl, 1, "File not found")?;
        return Err(io::Error::new(io::ErrorKind::NotFound, "file not found"));
    }

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(cl)?;
    let mut block_nr: u16 = 1;

    loop {
        let mut filebuf = [0; 512];
        let len = file.read(&mut filebuf);
        let len = match len {
            Ok(n) => n,
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue, /* retry */
            Err(err) => {
                handle_error(cl, 0, "File reading error")?;
                return Err(err);
            }
        };

        let mut sendbuf = vec![0x00, 0x03];  // opcode
        sendbuf.extend(block_nr.to_be_bytes().iter());
        sendbuf.extend(filebuf[0..len].iter());

        socket.send(&sendbuf)?;
        for _ in 1..5 {
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

fn file_allowed(filename: &str) -> bool {
    let path = Path::new(".").join(&filename);
    let path = match path.parent() {
        Some(p) => p,
        None => return false,
    };
    let path = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let cwd = match env::current_dir() {
        Ok(p) => p,
        Err(_) => return false,
    };

    return path.starts_with(cwd);
}

fn handle_rrq(cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
    let mut iter = buf.iter();

    let dataerr = io::Error::new(io::ErrorKind::InvalidData, "invalid data received");

    let fname_len = iter.position(|&x| x == 0);
    let fname_len = match fname_len {
        Some(len) => len,
        None => return Err(dataerr),
    };
    let fname_begin = 0;
    let fname_end = fname_begin + fname_len;
    let filename = String::from_utf8(buf[fname_begin .. fname_end].to_vec());
    let filename = match filename {
        Ok(fname) => fname,
        Err(_) => return Err(dataerr),
    };

    let mode_len = iter.position(|&x| x == 0);
    let mode_len = match mode_len {
        Some(len) => len,
        None => return Err(dataerr),
    };
    let mode_begin = fname_end + 1;
    let mode_end = mode_begin + mode_len;
    let mode = String::from_utf8(buf[mode_begin .. mode_end].to_vec());
    let mode = match mode {
        Ok(m) => m.to_lowercase(),
        Err(_) => return Err(dataerr),
    };

    match mode.as_ref() {
        "octet" => (),
        _ => handle_error(cl, 0, "Unsupported mode")?,
    }

    match file_allowed(&filename) {
        true => (),
        false => {
            handle_error(cl, 2, "Permission denied")?;
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"));
        }
    }

    match send_file(&cl, &filename) {
        Ok(_) => println!("Sent {} to {}.", filename, cl),
        Err(_) => println!("Sending {} to {} failed.", filename, cl),
    }
    Ok(())
}

fn handle_error(cl: &SocketAddr, code: u16, msg: &str) -> Result<(), io::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(cl)?;

    let mut buf = vec![0x00, 0x05];  // opcode
    buf.extend(code.to_be_bytes().iter());
    buf.extend(msg.as_bytes());

    socket.send(&buf)?;
    Ok(())
}

fn handle_client(cl: &SocketAddr, buf: &[u8]) -> Result<(), io::Error> {
    let opcode = u16::from_be_bytes([buf[0], buf[1]]);

    match opcode {
        1 /* RRQ */ => handle_rrq(&cl, &buf[2..])?,
        2 /* WRQ */ => handle_wrq(&cl, &buf[2..])?,
        5 /* ERROR */ => println!("Received ERROR from {}", cl),
        _ => handle_error(cl, 4, "Unexpected opcode")?,
    }
    Ok(())
}

fn drop_privs() -> Result<(), Box<Error>> {
    let root_uid = Uid::from_raw(0);
    let root_gid = Gid::from_raw(0);
    let unpriv_uid = Uid::from_raw(65534);
    let unpriv_gid = Gid::from_raw(65534);

    if Gid::current() == root_gid || Gid::effective() == root_gid {
        setresgid(unpriv_gid, unpriv_gid, unpriv_gid)?;
    }

    if Uid::current() == root_uid || Uid::effective() == root_uid {
        setresuid(unpriv_uid, unpriv_uid, unpriv_uid)?;
    }

    Ok(())
}

fn main() {
    let socket = match UdpSocket::bind("0.0.0.0:69") {
        Ok(s) => s,
        Err(err) => {
            println!("Binding a socket failed: {}", err);
            return;
        }
    };
    match drop_privs() {
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

        match handle_client(&src, &buf[0..n]) {
            /* errors intentionally ignored */
            _ => (),
        }
    }
}
