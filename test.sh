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

TMPDIR1=$(mktemp -d)
TMPDIR2=$(mktemp -d)

cleanup() {
	cleanup_atftpd
	cleanup_rtftpd
	cleanup_files
	rmdir "$TMPDIR1" "$TMPDIR2"
}

cleanup_files() {
	rm -f "$TMPDIR1/testfile" "$TMPDIR2/testfile"
}

compare_files() {
	cmp "$TMPDIR1/testfile" "$TMPDIR2/testfile" 1>/dev/null
}

init_atftpd() {
	$ATFTPD --port $PORT --user "$USER" --group "$GROUP" --daemon "$TMPDIR2"
}

init_rtftpd() {
	$SSD --background --exec "$RTFTPD" --start -- -p $PORT -d "$TMPDIR2" 1>/dev/null
}

init_testfile() {
	cleanup_files
	dd if=/dev/urandom of="$TMPDIR1/testfile" bs=1M count=100 2>/dev/null
}

cleanup_atftpd() {
	killall -q -9 $ATFTPD || true
}

cleanup_rtftpd() {
	killall -q -9 "$RTFTPD" || true
}

test_atftpd_rx() {
	init_testfile
	printf "atftpd rx: "
	$RTFTPC -p testfile 127.0.0.1:$PORT 1>/dev/null
	compare_files
	printf "ok"
}

test_atftpd_tx() {
	printf "atftpd tx: "
	rm -f testfile
	$RTFTPC -g testfile 127.0.0.1:$PORT 1>/dev/null
	compare_files
	printf "ok"
}

test_atftpc_tx() {
	init_testfile
	printf "atftpc tx: "
	$ATFTPC -p -l testfile -r testfile 127.0.0.1 $PORT 1>/dev/null
	compare_files
	printf "ok"
}

test_atftpc_tx_blksize() {
	init_testfile
	printf "atftpc tx (blksize 1428): "
	$ATFTPC -p -l testfile -r testfile --option "blksize 1428" 127.0.0.1 $PORT 1>/dev/null 2>&1
	compare_files
	printf "ok"
}

test_atftpc_rx() {
	printf "atftpc rx: "
	rm -f testfile
	$ATFTPC -g -l testfile -r testfile 127.0.0.1 $PORT 1>/dev/null
	compare_files
	printf "ok"
}

test_atftpc_rx_blksize() {
	printf "atftpc rx (blksize 1428): "
	rm -f testfile
	$ATFTPC -g -l testfile -r testfile --option "blksize 1428" 127.0.0.1 $PORT 1>/dev/null 2>&1
	compare_files
	printf "ok"
}

test_tftpc_tx() {
	init_testfile
	printf "tftpc tx: "
	printf "connect 127.0.0.1 %d\\nmode binary\\nput testfile\\n" $PORT | $TFTPC 1>/dev/null
	compare_files
	printf "ok"
}

test_tftpc_rx() {
	printf "tftpc rx: "
	rm -f testfile
	printf "connect 127.0.0.1 %d\\nmode binary\\nget testfile\\n" $PORT | $TFTPC 1>/dev/null
	compare_files
	printf "ok"
}

trap cleanup 0 1 2

cd "$TMPDIR1"

if [ -x $ATFTPD ]; then
	init_atftpd
	time test_atftpd_rx
	time test_atftpd_tx
	cleanup_atftpd
fi
if [ -x $ATFTPC ]; then
	init_rtftpd
	time test_atftpc_tx
	time test_atftpc_tx_blksize
	time test_atftpc_rx
	time test_atftpc_rx_blksize
	cleanup_rtftpd
fi
if [ -x $TFTPC ]; then
	init_rtftpd
	time test_tftpc_tx
	time test_tftpc_rx
	cleanup_rtftpd
fi

