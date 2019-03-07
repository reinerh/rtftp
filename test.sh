#!/bin/bash

set -e

PORT=12345
USER=$(whoami)
GROUP=$(groups | cut -d' ' -f 1)

SSD=/sbin/start-stop-daemon

RTFTPC=$(pwd)/target/release/rtftpc
RTFTPD=$(pwd)/target/release/rtftpd

ATFTPC=/usr/bin/atftp
ATFTPD=/usr/sbin/atftpd

TFTPC=/usr/bin/tftp

CLIENTDIR=$(mktemp -d)
SERVERDIR=$(mktemp -d)

cleanup() {
	atftpd_cleanup
	rtftpd_cleanup
	rm -f "$CLIENTDIR/testfile" "$SERVERDIR/testfile"
	rmdir "$CLIENTDIR" "$SERVERDIR"
}

compare_files() {
	cmp "$CLIENTDIR/testfile" "$SERVERDIR/testfile" 1>/dev/null
}

atftpd() {
	$ATFTPD --port $PORT --user "$USER" --group "$GROUP" --daemon "$SERVERDIR"
}

atftpc_tx() {
	$ATFTPC -p -l testfile -r testfile 127.0.0.1 $PORT 1>/dev/null
}

atftpc_rx() {
	$ATFTPC -g -l testfile -r testfile 127.0.0.1 $PORT 1>/dev/null
}

atftpc_blksize1428_tx() {
	$ATFTPC -p -l testfile -r testfile --option "blksize 1428" 127.0.0.1 $PORT 1>/dev/null 2>&1
}

atftpc_blksize1428_rx() {
	$ATFTPC -g -l testfile -r testfile --option "blksize 1428" 127.0.0.1 $PORT 1>/dev/null 2>&1
}

tftpc_tx() {
	printf "connect 127.0.0.1 %d\\nmode binary\\nput testfile\\n" $PORT | $TFTPC 1>/dev/null
}

tftpc_rx() {
	printf "connect 127.0.0.1 %d\\nmode binary\\nget testfile\\n" $PORT | $TFTPC 1>/dev/null
}

rtftpd() {
	$SSD --background --exec "$RTFTPD" --start -- -p $PORT -d "$SERVERDIR" 1>/dev/null
}

rtftpc_tx() {
	$RTFTPC -p testfile 127.0.0.1:$PORT 1>/dev/null
}

rtftpc_rx() {
	$RTFTPC -g testfile 127.0.0.1:$PORT 1>/dev/null
}

atftpd_cleanup() {
	killall -q -9 $ATFTPD 2>/dev/null || true
}

rtftpd_cleanup() {
	killall -q -9 "$RTFTPD" 2>/dev/null || true
}


test_transfer() {
	client=$1
	server=$2

	$server

	dd if=/dev/urandom of="$CLIENTDIR/testfile" bs=1M count=100 2>/dev/null

	time (
		printf "%s TX (to %s): " $client $server
		${client}_tx
		compare_files
		printf "ok"
	)
	rm -f "$CLIENTDIR/testfile"

	time (
		printf "%s RX (from %s): " $client $server
		${client}_rx
		compare_files
		printf "ok"
	)
	rm -f "$SERVERDIR/testfile"

	${server}_cleanup
}

trap cleanup 0 1 2

if [ ! -x "$RTFTPC" ] || [ ! -x "$RTFTPD" ]; then
	cargo build --release
fi

cd "$CLIENTDIR"

if [ -x $ATFTPD ]; then
	test_transfer rtftpc atftpd
fi
if [ -x $ATFTPC ]; then
	test_transfer atftpc rtftpd
	test_transfer atftpc_blksize1428 rtftpd
fi
if [ -x $TFTPC ]; then
	test_transfer tftpc rtftpd
fi

