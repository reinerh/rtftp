use std::net::{SocketAddr,UdpSocket};
use std::fs::File;
use std::io::prelude::*;

fn handle_wrq(_cl: &SocketAddr, _buf: &[u8]) {
}

fn wait_for_ack(sock: &UdpSocket, expected_block: u16) {
    let mut buf = [0; 4];
    sock.recv(&mut buf).expect("recv");

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let block_nr = u16::from_be_bytes([buf[2], buf[3]]);

    if opcode != 4 {
        // error
    }
    if block_nr != expected_block {
        // error
    }
}

fn send_file(cl: &SocketAddr, filename: &str) {
    let mut file = File::open(filename).expect("open");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
    socket.connect(cl).expect("connect");
    let mut block_nr: u16 = 1;

    loop {
        let mut filebuf = [0; 512];
        let n = file.read(&mut filebuf).expect("read");

        let mut sendbuf = vec![0x00, 0x03];  // opcode
        sendbuf.extend(block_nr.to_be_bytes().iter());
        sendbuf.extend(filebuf[0..n].iter());

        socket.send(&sendbuf).expect("send");
        wait_for_ack(&socket, block_nr);

        if n < 512 {
            /* this was the last block */
            break;
        }

        /* increment with rollover on overflow */
        block_nr = block_nr.wrapping_add(1);
    }
}

fn handle_rrq(cl: &SocketAddr, buf: &[u8]) {
    let mut iter = buf.iter();

    let fname_len = iter.position(|&x| x == 0).expect("not found");
    let fname_begin = 0;
    let fname_end = fname_begin + fname_len;
    let filename = String::from_utf8(buf[fname_begin .. fname_end].to_vec()).expect("str");

    let mode_len = iter.position(|&x| x == 0).expect("not found");
    let mode_begin = fname_end + 1;
    let mode_end = mode_begin + mode_len;
    let mode = String::from_utf8(buf[mode_begin .. mode_end].to_vec()).expect("str");
    let mode = mode.to_lowercase();

    match mode.as_ref() {
        "octet" => println!("octet mode"),
        _ => handle_error(cl, 0, "Unsupported mode"),
    }

    println!("Sending {} to {}", filename, cl);
    send_file(&cl, &filename);
}

fn handle_error(cl: &SocketAddr, code: u16, msg: &str) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
    socket.connect(cl).expect("connect");

    let mut buf = vec![0x00, 0x05];  // opcode
    buf.extend(code.to_be_bytes().iter());
    buf.extend(msg.as_bytes());

    socket.send(&buf).expect("send");
}

fn handle_client(cl: &SocketAddr, buf: &[u8]) {
    let opcode = u16::from_be_bytes([buf[0], buf[1]]);

    match opcode {
        1 /* RRQ */ => handle_rrq(&cl, &buf[2..]),
        2 /* WRQ */ => handle_wrq(&cl, &buf[2..]),
        5 /* ERROR */ => println!("Received ERROR from {}", cl),
        _ => handle_error(cl, 4, "Unexpected opcode"),
    }
}

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:12345").expect("bind");

    loop {
        let mut buf = [0; 2048];
        let (n, src) = socket.recv_from(&mut buf).expect("recv");

        handle_client(&src, &buf[0..n]);
    }
}
