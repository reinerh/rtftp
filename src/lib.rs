/*
 * Copyright 2019 Reiner Herrmann <reiner@reiner-h.de>
 * License: GPL-3+
 */

use std::net::{SocketAddr,UdpSocket};
use std::fs::File;
use std::collections::HashMap;
use std::path::{Path,PathBuf};
use std::io;
use std::io::prelude::*;
use std::time::Duration;

#[repr(u16)]
pub enum Opcodes {
    RRQ   = 0x01,
    WRQ   = 0x02,
    DATA  = 0x03,
    ACK   = 0x04,
    ERROR = 0x05,
    OACK  = 0x06,
}

pub struct TftpOptions {
    blksize: usize,
    timeout: u8,
    tsize: usize,
}

pub struct Tftp {
    options: TftpOptions,
}

fn default_options() -> TftpOptions {
    TftpOptions {
        blksize: 512,
        timeout: 3,
        tsize: 0,
    }
}

impl Tftp {

    pub fn new() -> Tftp {
        Tftp{
            options: default_options(),
        }
    }

    fn get_tftp_str(&self, buf: &[u8]) -> Option<(String, usize)> {
        let mut iter = buf.iter();

        let len = match iter.position(|&x| x == 0) {
            Some(l) => l,
            None => return None,
        };
        let val = match String::from_utf8(buf[0 .. len].to_vec()) {
            Ok(v) => v,
            Err(_) => return None,
        };

        return Some((val, len));
    }

    pub fn append_option(&self, buf: &mut Vec<u8>, key: &str, val: &str) {
        buf.extend(key.bytes());
        buf.push(0x00);
        buf.extend(val.bytes());
        buf.push(0x00);
    }

    fn wait_for_ack(&self, sock: &UdpSocket, expected_block: u16) -> Result<bool, io::Error> {
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

        if opcode == Opcodes::ACK as u16 && block_nr == expected_block {
            return Ok(true)
        }

        Ok(false)
    }

    pub fn ack_options(&self, sock: &UdpSocket, options: &HashMap<String, String>, ackwait: bool) -> Result<(), io::Error> {
        if options.is_empty() {
            if !ackwait {
                /* it's a WRQ, send normal ack to start transfer */
                self.send_ack(&sock, 0)?;
            }
            return Ok(())
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
                "blksize" => {
                    match val.parse() {
                        Ok(b) if b >= 8 && b <= 65464 => {
                            self.options.blksize = b;
                            true
                        }
                        _ => false
                    }
                }
                "timeout" => {
                    match val.parse() {
                        Ok(t) if t >= 1 => {
                            self.options.timeout = t;
                            true
                        }
                        _ => false
                    }
                }
                "tsize" => {
                    match val.parse() {
                        Ok(t) => {
                            self.options.tsize = t;
                            true
                        }
                        _ => false
                    }
                }
                _ => false
            }
        });

        sock.set_read_timeout(Some(Duration::from_secs(self.options.timeout as u64)))?;

        return Ok(());
    }

    pub fn parse_options(&self, buf: &[u8]) -> HashMap<String, String> {
        let mut options = HashMap::new();

        let mut pos = 0;
        loop {
            let (key, len) = match self.get_tftp_str(&buf[pos ..]) {
                Some(args) => args,
                None => break,
            };
            pos += len + 1;

            let (val, len) = match self.get_tftp_str(&buf[pos ..]) {
                Some(args) => args,
                None => break,
            };
            pos += len + 1;

            options.insert(key, val);
        }

        return options;
    }

    pub fn parse_file_mode_options(&self, buf: &[u8]) -> Result<(PathBuf, String, HashMap<String, String>), io::Error> {
        let dataerr = io::Error::new(io::ErrorKind::InvalidData, "invalid data received");

        let mut pos = 0;
        let (filename, len) = match self.get_tftp_str(&buf[pos ..]) {
            Some(args) => args,
            None => return Err(dataerr),
        };
        pos += len + 1;

        let filename = Path::new(&filename);

        let (mode, len) = match self.get_tftp_str(&buf[pos ..]) {
            Some((m,l)) => (m.to_lowercase(), l),
            None => return Err(dataerr),
        };
        pos += len + 1;

        let options = self.parse_options(&buf[pos ..]);

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
                    },
                    Ok(false) => continue,
                    Err(e) => return Err(e),
                };
            }
            if !acked {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "ack timeout"))
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

            let _opcode = match u16::from_be_bytes([buf[0], buf[1]]) {
                opc if opc == Opcodes::DATA as u16 => (),
                _ => return Err(io::Error::new(io::ErrorKind::Other, "unexpected opcode")),
            };
            if u16::from_be_bytes([buf[2], buf[3]]) != block_nr {
                /* already received or packets were missed, re-acknowledge */
                self.send_ack(&sock, block_nr - 1)?;
                continue;
            }

            let databuf = &buf[4..len];
            file.write_all(databuf)?;

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