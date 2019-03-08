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
pub enum Opcodes {
    RRQ   = 0x01,
    WRQ   = 0x02,
    DATA  = 0x03,
    ACK   = 0x04,
    ERROR = 0x05,
    OACK  = 0x06,
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
    progress_cb: Option<ProgressCallback>,
}

fn default_options() -> TftpOptions {
    TftpOptions {
        blksize: 512,
        timeout: 3,
        tsize: 0,
    }
}

impl Default for Tftp {
    fn default() -> Tftp {
        Tftp {
            options: default_options(),
            progress_cb: None,
        }
    }
}

impl Tftp {
    pub fn new() -> Tftp {
        Default::default()
    }

    fn get_tftp_str(&self, buf: &[u8]) -> Option<(String, usize)> {
        let mut iter = buf.iter();

        let len = match iter.position(|&x| x == 0) {
            Some(l) => l,
            None => return None,
        };
        let val = match String::from_utf8(buf[0..len].to_vec()) {
            Ok(v) => v,
            Err(_) => return None,
        };

        Some((val, len))
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
        if opcode != Opcodes::ERROR as u16 {
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

        if opcode == Opcodes::ACK as u16 && block_nr == expected_block {
            return Ok(true);
        } else if opcode == Opcodes::ERROR as u16 {
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
        buf.extend((Opcodes::OACK as u16).to_be_bytes().iter());

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
            let (key, len) = match self.get_tftp_str(&buf[pos..]) {
                Some(args) => args,
                None => break,
            };
            pos += len + 1;

            let (val, len) = match self.get_tftp_str(&buf[pos..]) {
                Some(args) => args,
                None => break,
            };
            pos += len + 1;

            options.insert(key, val);
        }

        options
    }

    pub fn parse_file_mode_options(&self, buf: &[u8]) -> Result<(PathBuf, String, HashMap<String, String>), io::Error> {
        let dataerr = io::Error::new(io::ErrorKind::InvalidData, "invalid data received");

        let mut pos = 0;
        let (filename, len) = match self.get_tftp_str(&buf[pos..]) {
            Some(args) => args,
            None => return Err(dataerr),
        };
        pos += len + 1;

        let filename = Path::new(&filename);

        let (mode, len) = match self.get_tftp_str(&buf[pos..]) {
            Some((m, l)) => (m.to_lowercase(), l),
            None => return Err(dataerr),
        };
        pos += len + 1;

        let options = self.parse_options(&buf[pos..]);

        Ok((filename.to_path_buf(), mode, options))
    }

    pub fn send_error(&self, socket: &UdpSocket, code: u16, msg: &str) -> Result<(), io::Error> {
        let mut buf = Vec::with_capacity(512);
        buf.extend((Opcodes::ERROR as u16).to_be_bytes().iter());
        buf.extend(code.to_be_bytes().iter());
        buf.extend(msg.as_bytes());

        socket.send(&buf)?;
        Ok(())
    }

    fn _send_ack(&self, sock: &UdpSocket, cl: Option<SocketAddr>, block_nr: u16) -> Result<(), io::Error> {
        let mut buf = Vec::with_capacity(4);
        buf.extend((Opcodes::ACK as u16).to_be_bytes().iter());
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

        loop {
            let mut filebuf = vec![0; self.options.blksize];
            let len = match file.read(&mut filebuf) {
                Ok(n) => n,
                Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue, /* retry */
                Err(err) => {
                    self.send_error(&socket, 0, "File reading error")?;
                    return Err(err);
                }
            };

            let mut sendbuf = Vec::with_capacity(4 + len);
            sendbuf.extend((Opcodes::DATA as u16).to_be_bytes().iter());
            sendbuf.extend(block_nr.to_be_bytes().iter());
            sendbuf.extend(filebuf[0..len].iter());

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
                opc if opc == Opcodes::DATA as u16 => (),
                opc if opc == Opcodes::ERROR as u16 => return Err(self.parse_error(&buf[..len])),
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode")),
            };
            if u16::from_be_bytes([buf[2], buf[3]]) != block_nr {
                /* already received or packets were missed, re-acknowledge */
                self.send_ack(&sock, block_nr - 1)?;
                continue;
            }

            let databuf = &buf[4..len];
            file.write_all(databuf)?;

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

        file.flush()?;

        Ok(())
    }
}
