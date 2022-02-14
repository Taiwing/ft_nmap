#!/usr/bin/env bash

function goodbye() {
	exit 0
}

SIG=1
while [ $SIG -lt 16 ]; do
	trap "goodbye" $SIG
	((SIG++))
done

function random_ipv4() {
	IPV4=""
	for i in $(seq 4); do
		RAND_NUM=$(($RANDOM%256))
		if [ ${#IPV4} -eq 0 ]; then
			IPV4=$RAND_NUM
		else
			IPV4="${IPV4}.${RAND_NUM}"
		fi
	done
	echo $IPV4
}

while [ 42 ]; do
	IP=$(random_ipv4)
	if ping -c 1 -W 1 $IP > /dev/null; then
		echo $IP
		echo $IP >&2
	fi
done
