/*
 * Copyright 2019 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub static VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

/// * `cur` - current number of bytes
/// * `total` - total number of bytes; 0 if unknown
/// * `state` - state that was returned in previous call
/// Returns state that should get passed in next invocation
type ProgressCallback = fn(cur: u64, total: u64, state: u64) -> u64;

#[repr(u16)]
pub enum Opcode {
    RRQ   = 0x01,
    WRQ   = 0x02,
    DATA  = 0x03,
    ACK   = 0x04,
    ERROR = 0x05,
    OACK  = 0x06,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Mode {
    OCTET,
    NETASCII,
}

#[derive(Clone, Copy)]
pub struct TftpOptions {
    blksize: usize,
    timeout: u8,
    tsize: u64,
}

#[derive(Clone, Copy)]
pub struct Tftp {
    options: TftpOptions,
    mode: Mode,
    progress_cb: Option<ProgressCallback>,
}

fn default_options() -> TftpOptions {
    TftpOptions {
        blksize: 512,
        timeout: 3,
        tsize: 0,
    }
}

fn netascii_to_octet(buf: &[u8], previous_cr: bool) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(buf.len());

    let mut prev_cr = previous_cr;
    for b in buf {
        match *b {
            b'\r' => {
                if prev_cr {
                    out.push(b'\r');
                }
                prev_cr = true;
                continue;
            }
            b'\0' if prev_cr => out.push(b'\r'),
            b'\n' if prev_cr => out.push(b'\n'),
            _ => out.push(*b),
        }
        prev_cr = false;
    }
    (out, prev_cr)
}

fn octet_to_netascii(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * buf.len());

    for b in buf {
        match *b {
            b'\r' => out.extend(b"\r\0"),
            b'\n' => out.extend(b"\r\n"),
            _ => out.push(*b),
        }
    }
    out
}

impl Default for Tftp {
    fn default() -> Tftp {
        Tftp {
            options: default_options(),
            mode: Mode::OCTET,
            progress_cb: None,
        }
    }
}

impl Tftp {
    pub fn new() -> Tftp {
        Default::default()
    }

    pub fn transfersize(&self, file: &mut File) -> Result<u64, io::Error> {
        match self.mode {
            Mode::OCTET => return Ok(file.metadata().expect("failed to get metadata").len()),
            Mode::NETASCII => {},
        }

        let mut total_size = 0;
        loop {
            let mut buf = [0; 4096];
            let size = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(s) => s,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            total_size += size as u64;
            /* each \r and \n will take two bytes in netascii output */
            total_size += buf[0..size].iter()
                                      .filter(|&x| *x == b'\r' || *x == b'\n')
                                      .count() as u64;
        }

        file.seek(io::SeekFrom::Start(0))?;
        Ok(total_size)
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    fn get_tftp_str(&self, buf: &[u8]) -> Option<String> {
        let mut iter = buf.iter();

        let len = match iter.position(|&x| x == 0) {
            Some(l) => l,
            None => return None,
        };
        let val = match String::from_utf8(buf[0..len].to_vec()) {
            Ok(v) => v,
            Err(_) => return None,
        };

        Some(val)
    }

    pub fn set_progress_callback(&mut self, cb: ProgressCallback) {
        self.progress_cb = Some(cb);
    }

    fn transfer_size(&self, file: &File) -> u64 {
        match file.metadata() {
            Ok(ref m) if m.len() > 0 => m.len(),
            _ => self.options.tsize,
        }
    }

    pub fn append_option(&self, buf: &mut Vec<u8>, key: &str, val: &str) {
        buf.extend(key.bytes());
        buf.push(0x00);
        buf.extend(val.bytes());
        buf.push(0x00);
    }

    pub fn parse_error(&self, buf: &[u8]) -> std::io::Error {
        let mut kind = std::io::ErrorKind::InvalidData;
        let mut error = String::from("Invalid packet received");

        if buf.len() < 5 {
            return std::io::Error::new(kind, error);
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        if opcode != Opcode::ERROR as u16 {
            return std::io::Error::new(kind, error);
        }

        let errorcode = u16::from_be_bytes([buf[2], buf[3]]);
        error = match String::from_utf8(buf[4..].to_vec()) {
            Ok(e) => e,
            Err(_) => return std::io::Error::new(kind, error),
        };

        kind = match errorcode {
            1 => std::io::ErrorKind::NotFound,
            2 => std::io::ErrorKind::PermissionDenied,
            3 => std::io::ErrorKind::UnexpectedEof,
            4 => std::io::ErrorKind::InvalidData,
            5 => std::io::ErrorKind::InvalidInput,
            6 => std::io::ErrorKind::AlreadyExists,
            7 => std::io::ErrorKind::NotFound,
            _ => std::io::ErrorKind::InvalidData,
        };

        std::io::Error::new(kind, error)
    }

    fn wait_for_ack(&self, sock: &UdpSocket, expected_block: u16) -> Result<bool, io::Error> {
        let mut buf = [0; 512];
        let len = match sock.recv(&mut buf) {
            Ok(l) => l,
            Err(ref error) if [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&error.kind()) => {
                return Ok(false);
            }
            Err(err) => return Err(err),
        };

        if len < 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid data received"));
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

        if opcode == Opcode::ACK as u16 && block_nr == expected_block {
            return Ok(true);
        } else if opcode == Opcode::ERROR as u16 {
            return Err(self.parse_error(&buf[4..]));
        }

        Ok(false)
    }

    pub fn ack_options(&self, sock: &UdpSocket, options: &HashMap<String, String>, ackwait: bool) -> Result<(), io::Error> {
        if options.is_empty() {
            if !ackwait {
                /* it's a WRQ, send normal ack to start transfer */
                self.send_ack(&sock, 0)?;
            }
            return Ok(());
        }

        let mut buf = Vec::with_capacity(512);
        buf.extend((Opcode::OACK as u16).to_be_bytes().iter());

        for (key, val) in options {
            self.append_option(&mut buf, key, val);
        }

        for _ in 1..5 {
            sock.send(&buf)?;
            if !ackwait {
                return Ok(());
            }
            match self.wait_for_ack(&sock, 0) {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(e) => return Err(e),
            };
        }

        Err(io::Error::new(io::ErrorKind::TimedOut, "ack timeout"))
    }

    pub fn init_tftp_options(&mut self, sock: &UdpSocket, options: &mut HashMap<String, String>) -> Result<(), io::Error> {
        self.options = default_options();

        options.retain(|key, val| {
            let val = val.to_lowercase();
            match key.to_lowercase().as_str() {
                "blksize" => match val.parse() {
                    Ok(b) if b >= 8 && b <= 65464 => {
                        self.options.blksize = b;
                        true
                    }
                    _ => false,
                },
                "timeout" => match val.parse() {
                    Ok(t) if t >= 1 => {
                        self.options.timeout = t;
                        true
                    }
                    _ => false,
                },
                "tsize" => match val.parse() {
                    Ok(t) => {
                        self.options.tsize = t;
                        true
                    }
                    _ => false,
                },
                _ => false,
            }
        });

        sock.set_read_timeout(Some(Duration::from_secs(u64::from(self.options.timeout))))?;

        Ok(())
    }

    pub fn parse_options(&self, buf: &[u8]) -> HashMap<String, String> {
        let mut options = HashMap::new();

        let mut pos = 0;
        loop {
            let key = match self.get_tftp_str(&buf[pos..]) {
                Some(k) => k,
                None => break,
            };
            pos += key.len() + 1;

            let val = match self.get_tftp_str(&buf[pos..]) {
                Some(v) => v,
                None => break,
            };
            pos += val.len() + 1;

            options.insert(key, val);
        }

        options
    }

    pub fn parse_file_mode_options(&self, buf: &[u8]) -> Result<(PathBuf, String, HashMap<String, String>), io::Error> {
        let dataerr = io::Error::new(io::ErrorKind::InvalidData, "invalid data received");

        let mut pos = 0;
        let filename = match self.get_tftp_str(&buf[pos..]) {
            Some(f) => f,
            None => return Err(dataerr),
        };
        pos += filename.len() + 1;

        let filename = Path::new(&filename);

        let mode = match self.get_tftp_str(&buf[pos..]) {
            Some(m) => m.to_lowercase(),
            None => return Err(dataerr),
        };
        pos += mode.len() + 1;

        let options = self.parse_options(&buf[pos..]);

        Ok((filename.to_path_buf(), mode, options))
    }

    pub fn send_error(&self, socket: &UdpSocket, code: u16, msg: &str) -> Result<(), io::Error> {
        let mut buf = Vec::with_capacity(512);
        buf.extend((Opcode::ERROR as u16).to_be_bytes().iter());
        buf.extend(code.to_be_bytes().iter());
        buf.extend(msg.as_bytes());

        socket.send(&buf)?;
        Ok(())
    }

    fn _send_ack(&self, sock: &UdpSocket, cl: Option<SocketAddr>, block_nr: u16) -> Result<(), io::Error> {
        let mut buf = Vec::with_capacity(4);
        buf.extend((Opcode::ACK as u16).to_be_bytes().iter());
        buf.extend(block_nr.to_be_bytes().iter());

        match cl {
            Some(remote) => { sock.send_to(&buf, remote)?; }
            None => { sock.send(&buf)?; }
        }
        Ok(())
    }

    pub fn send_ack(&self, sock: &UdpSocket, block_nr: u16) -> Result<(), io::Error> {
        self._send_ack(sock, None, block_nr)
    }

    pub fn send_ack_to(&self, sock: &UdpSocket, cl: SocketAddr, block_nr: u16) -> Result<(), io::Error> {
        self._send_ack(sock, Some(cl), block_nr)
    }

    pub fn send_file(&self, socket: &UdpSocket, file: &mut File) -> Result<(), io::Error> {
        let mut block_nr: u16 = 1;
        let mut transferred = 0;
        let mut prog_update = 0;
        let tsize = self.transfer_size(file);

        /* holds bytes from netascii conversion that did not fit in tx buffer */
        let mut overflow = Vec::with_capacity(2 * self.options.blksize);

        loop {
            let mut filebuf = vec![0; self.options.blksize - overflow.len()];
            let mut len = match file.read(&mut filebuf) {
                Ok(n) => n,
                Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue, /* retry */
                Err(err) => {
                    self.send_error(&socket, 0, "File reading error")?;
                    return Err(err);
                }
            };

            /* take care of netascii conversion */
            let mut databuf = filebuf[0..len].to_vec();
            match self.mode {
                Mode::OCTET => {},
                Mode::NETASCII => {
                    overflow.extend(octet_to_netascii(&databuf));
                    databuf = overflow.clone();
                    if overflow.len() > self.options.blksize {
                        overflow = databuf.split_off(self.options.blksize);
                    } else {
                        overflow.clear();
                    }
                    len = databuf.len();
                }
            }

            let mut sendbuf = Vec::with_capacity(4 + len);
            sendbuf.extend((Opcode::DATA as u16).to_be_bytes().iter());
            sendbuf.extend(block_nr.to_be_bytes().iter());
            sendbuf.extend(databuf.iter());

            let mut acked = false;
            for _ in 1..5 {
                /* try a couple of times to send data, in case of timeouts
                   or re-ack of previous data */
                socket.send(&sendbuf)?;
                match self.wait_for_ack(&socket, block_nr) {
                    Ok(true) => {
                        acked = true;
                        break;
                    }
                    Ok(false) => continue,
                    Err(e) => return Err(e),
                };
            }
            if !acked {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "ack timeout"));
            }

            transferred += len as u64;
            if let Some(cb) = self.progress_cb {
                prog_update = cb(transferred, tsize, prog_update);
            }

            if len < self.options.blksize {
                /* this was the last block */
                break;
            }

            /* increment with rollover on overflow */
            block_nr = block_nr.wrapping_add(1);
        }
        Ok(())
    }

    pub fn recv_file(&self, sock: &UdpSocket, file: &mut File) -> Result<(), io::Error> {
        let mut block_nr: u16 = 1;
        let mut prog_update = 0;
        let mut transferred = 0;
        let mut netascii_state = false;
        let tsize = self.transfer_size(file);

        loop {
            let mut buf = vec![0; 4 + self.options.blksize + 1]; // +1 for later size check
            let mut len = 0;

            for _ in 1..5 {
                len = match sock.recv(&mut buf) {
                    Ok(n) => n,
                    Err(ref error) if [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut].contains(&error.kind()) => {
                        /* re-ack previous and try to recv again */
                        self.send_ack(&sock, block_nr - 1)?;
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                break;
            }
            if len < 4 || len > 4 + self.options.blksize {
                /* max size: 2 + 2 + blksize */
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected size"));
            }

            match u16::from_be_bytes([buf[0], buf[1]]) {  // opcode
                opc if opc == Opcode::DATA as u16 => (),
                opc if opc == Opcode::ERROR as u16 => return Err(self.parse_error(&buf[..len])),
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode")),
            };
            if u16::from_be_bytes([buf[2], buf[3]]) != block_nr {
                /* already received or packets were missed, re-acknowledge */
                self.send_ack(&sock, block_nr - 1)?;
                continue;
            }

            let mut databuf = buf[4..len].to_vec();
            match self.mode {
                Mode::OCTET => {},
                Mode::NETASCII => {
                    let (converted, state) = netascii_to_octet(&databuf, netascii_state);
                    databuf = converted;
                    netascii_state = state;
                }
            }
            file.write_all(&databuf)?;

            transferred += (len - 4) as u64;
            if let Some(cb) = self.progress_cb {
                prog_update = cb(transferred, tsize, prog_update);
            }

            self.send_ack(&sock, block_nr)?;
            block_nr = block_nr.wrapping_add(1);

            if len < 4 + self.options.blksize {
                break;
            }
        }

        if netascii_state {
            /* the file ended with an incomplete \r encoding */
            file.write_all(&[b'\r'])?;
        }

        file.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tftp_str() {
        let tftp = Tftp::new();

        let mut buf = Vec::with_capacity(100);
        assert_eq!(tftp.get_tftp_str(&buf), None);

        buf.extend("key".bytes());
        assert_eq!(tftp.get_tftp_str(&buf), None);

        buf.push(0x00);
        buf.extend("value".bytes());
        buf.push(0x00);
        /* empty option */
        buf.push(0x00);

        let mut pos = 0;
        let val = tftp.get_tftp_str(&buf).unwrap();
        assert_eq!(val, "key");
        pos += val.len() + 1;
        let val = tftp.get_tftp_str(&buf[pos..]).unwrap();
        assert_eq!(val, "value");
        pos += val.len() + 1;
        let val = tftp.get_tftp_str(&buf[pos..]).unwrap();
        assert_eq!(val, "");
    }

    #[test]
    fn test_parse_options() {
        let tftp = Tftp::new();

        let mut buf = Vec::with_capacity(100);
        let opts = tftp.parse_options(&buf);
        assert_eq!(opts.len(), 0);

        buf.extend("blksize\x001234\x00tsize\x000\x00incomplete".bytes());
        let opts = tftp.parse_options(&buf);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts["blksize"], "1234");
        assert_eq!(opts["tsize"], "0");
        assert_eq!(opts.contains_key("incomplete"), false);
    }

    #[test]
    fn test_parse_file_mode_options() {
        let tftp = Tftp::new();

        let mut buf = Vec::with_capacity(100);
        assert_eq!(tftp.parse_file_mode_options(&buf).is_err(), true);
        buf.extend("FileName\x00".bytes());
        assert_eq!(tftp.parse_file_mode_options(&buf).is_err(), true);
        buf.extend("NetASCII\x00".bytes());
        let (filename, mode, opts) = tftp.parse_file_mode_options(&buf).unwrap();
        assert_eq!(filename, PathBuf::from("FileName"));
        assert_eq!(mode, "netascii");
        assert_eq!(opts.len(), 0);

        buf.extend("blksize\x001024\x00".bytes());
        let (filename, mode, opts) = tftp.parse_file_mode_options(&buf).unwrap();
        assert_eq!(filename, PathBuf::from("FileName"));
        assert_eq!(mode, "netascii");
        assert_eq!(opts.len(), 1);
        assert_eq!(opts["blksize"], "1024");
    }

    #[test]
    fn test_append_option() {
        let tftp = Tftp::new();

        let mut buf = Vec::with_capacity(100);
        tftp.append_option(&mut buf, "key", "value");
        assert_eq!(buf, "key\x00value\x00".as_bytes());
    }

    #[test]
    fn test_netascii_to_octet() {
        assert_eq!(netascii_to_octet(b"\r\nfoo\r\0bar", false), (b"\nfoo\rbar".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\r\0", false), (b"\r".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\r\n", false), (b"\n".to_vec(), false));
        assert_eq!(netascii_to_octet(b"", false), (b"".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\n\0\n\0", false), (b"\n\0\n\0".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\r\r\n", false), (b"\r\n".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\r\n\r\n", false), (b"\n\n".to_vec(), false));
        assert_eq!(netascii_to_octet(b"test\r\0", false), (b"test\r".to_vec(), false));
        assert_eq!(netascii_to_octet(b"test\r", false), (b"test".to_vec(), true));
        assert_eq!(netascii_to_octet(b"\r", false), (b"".to_vec(), true));
        assert_eq!(netascii_to_octet(b"\0test", true), (b"\rtest".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\ntest", true), (b"\ntest".to_vec(), false));
        assert_eq!(netascii_to_octet(b"\n\r", true), (b"\n".to_vec(), true));
        assert_eq!(netascii_to_octet(b"", true), (b"".to_vec(), true));
        assert_eq!(netascii_to_octet(b"\r", true), (b"\r".to_vec(), true));
    }

    #[test]
    fn test_octet_to_netascii() {
        assert_eq!(octet_to_netascii(b"foobar"), b"foobar");
        assert_eq!(octet_to_netascii(b"foo\rbar\n"), b"foo\r\0bar\r\n");
        assert_eq!(octet_to_netascii(b"\r\n"), b"\r\0\r\n");
        assert_eq!(octet_to_netascii(b"\r\r\n\n"), b"\r\0\r\0\r\n\r\n");
        assert_eq!(octet_to_netascii(b"\r\0\r\n"), b"\r\0\0\r\0\r\n");
        assert_eq!(octet_to_netascii(b""), b"");
    }
}
