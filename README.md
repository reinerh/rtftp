# RusTFTP

A client and server implementation of the Trivial File Transfer Protocol,
written in Rust.

[![Crates.io](https://img.shields.io/crates/v/rtftp.svg)](https://crates.io/crates/rtftp)

Currently supported:

* RFC 1350 (TFTP revision 2)
* RFC 2347 (Option Extension)
* RFC 2348 (Blocksize Option)
* RFC 2349 (Timeout Interval and Transfer Size Options)

Non-standard options:

* blksize2: block size as a power of 2
* utimeout: timeout in microseconds

Use cargo to build the binaries (output dir is `target/release/`):

```bash
cargo build --release
```

To directly download, compile and install the binaries:

```bash
cargo install rtftp
```

## Usage

### Client

```bash
$ ./rtftpc --help
RusTFTP

./rtftpc [options] <remote>[:port]

Options:
    -h, --help          display usage information
    -g, --get FILE      download file from remote server
    -p, --put FILE      upload file to remote server
    -b, --blksize SIZE  negotiate a different block size (default: 1428)
    -n, --netascii      use netascii mode (instead of octet)
```

### Server

```bash
$ ./rtftpd --help
RusTFTP

./rtftpd [options] [directory]

Options:
    -h, --help          display usage information
    -p, --port PORT     port to listen on (default: 69)
    -u, --uid UID       user id to run as (default: 65534)
    -g, --gid GID       group id to run as (default: 65534)
    -r, --read-only     allow only reading/downloading of files (RRQ)
    -w, --write-only    allow only writing/uploading of files (WRQ)
    -t, --threads N     number of worker threads (default: 2)
```

## Notes

As the block number is two bytes long, the number of blocks is limited
to 65535 (with the first block starting at 1).
To support the transfer of files larger than 65535 blocks, it will wrap around
after reaching the maximum and start at 0 again, which is not defined in the
standard.

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
