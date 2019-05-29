#!/bin/sh

trap 'test -z "$pids" || kill $pids' EXIT

set -x -e
test -x ./query || go build ./cmd/query
test -x ./PR-DNSd || go build .
netstat -tlnp | grep -w :55533 || { test/test-srv.conf & pids="$!"; }
netstat -tlnp | grep -w :55333 || { ./PR-DNSd -listen :55333 -upstream 127.0.0.1:55533 -chroot '' & pids="${pids:+$pids }$!"; sleep 1;}

./query -server 127.0.0.1:55333 25.0.0.127.in-addr.arpa. PTR
./query -server 127.0.0.1:55333 test.example.com. A
./query -server 127.0.0.1:55333 25.0.0.127.in-addr.arpa. PTR
