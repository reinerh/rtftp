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

BUSYBOX=/bin/busybox

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

atftpc() {
	[ $TX -eq 1 ] && op="-p" || op="-g"
	[ -n "$NETASCII" ] && opts="--mode netascii"
	if [ -n "$BLKSIZE" ]; then
		$ATFTPC $op -l testfile -r testfile $opts --option "blksize $BLKSIZE" 127.0.0.1 $PORT 1>/dev/null 2>&1
	else
		$ATFTPC $op -l testfile -r testfile $opts 127.0.0.1 $PORT 1>/dev/null
	fi
}

tftpc() {
	[ $TX -eq 1 ] && op="put" || op="get"
	printf "connect 127.0.0.1 $PORT\\nmode binary\\n$op testfile\\n" | $TFTPC 1>/dev/null
}

rtftpd() {
	$SSD --background --exec "$RTFTPD" --start -- -p $PORT -d "$SERVERDIR" 1>/dev/null
}

rtftpc() {
	[ $TX -eq 1 ] && op="-p" || op="-g"
	[ -n "$BLKSIZE" ] && opts="--blksize $BLKSIZE"
	[ -n "$NETASCII" ] && opts="$opts -n"
	$RTFTPC $op testfile $opts 127.0.0.1:$PORT 1>/dev/null
}

busybox_tftpc() {
	[ $TX -eq 1 ] && op="-p" || op="-g"
	[ -n "$BLKSIZE" ] && opts="-b $BLKSIZE"
	$BUSYBOX tftp $op -l testfile -r testfile $opts 127.0.0.1 $PORT 1>/dev/null 2>&1
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
		printf "$client TX (to $server): "
		TX=1
		${client}
		compare_files
		printf "ok"
	)
	rm -f "$CLIENTDIR/testfile"

	time (
		printf "$client RX (from $server): "
		TX=0
		${client}
		compare_files
		printf "ok"
	)
	rm -f "$SERVERDIR/testfile"

	${server}_cleanup
}

trap cleanup 0 1 2

# make sure binaries are up-to-date
cargo build --release

cd "$CLIENTDIR"


# Defaults
printf "Testing with default configuration\\n"
test_transfer rtftpc rtftpd
[ -x $ATFTPD ]  && test_transfer rtftpc atftpd
[ -x $ATFTPC ]  && test_transfer atftpc rtftpd
[ -x $TFTPC ]   && test_transfer tftpc rtftpd
[ -x $BUSYBOX ] && test_transfer busybox_tftpc rtftpd

# with netascii mode
printf "\\n\\nTesting netascii transfers\\n"
NETASCII=1
test_transfer rtftpc rtftpd
[ -x $ATFTPD ] && test_transfer rtftpc atftpd
[ -x $ATFTPC ] && test_transfer atftpc rtftpd
unset NETASCII

# different block size
printf "\\n\\nTesting larger block sizes\\n"
BLKSIZE=1500
test_transfer rtftpc rtftpd
[ -x $ATFTPD ]  && test_transfer rtftpc atftpd
[ -x $ATFTPC ]  && test_transfer atftpc rtftpd
[ -x $BUSYBOX ] && test_transfer busybox_tftpc rtftpd
unset BLKSIZE

# blocksize and netascii
printf "\\n\\nTesting larger block sizes and netascii\\n"
BLKSIZE=1500
NETASCII=1
test_transfer rtftpc rtftpd
[ -x $ATFTPD ] && test_transfer rtftpc atftpd
[ -x $ATFTPC ] && test_transfer atftpc rtftpd
unset NETASCII
