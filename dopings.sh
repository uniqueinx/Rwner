#!/bin/bash
base_ip="197.40."

for ip in `seq 120 130`;do
	for ipp in `seq 1 255`;do
		ping -c 1 $base_ip$ip.$ipp| grep "bytes from" | cut -d" " -f4 | cut -d":" -f1 &
	done
done
