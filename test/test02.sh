#!/bin/sh

: "${key:=test/server.key}"
: "${crt:=test/server.crt}"
: "${crt_tmpl:=test/server.crt.tmpl}"

set -x -e
test -s "$key" || certtool -p --outfile "$key"
test -s "$crt" || {
  test -e "$crt_tmpl" || cat >"$crt_tmpl" <<EOF
cn=server
ip_address=127.0.0.1
EOF
  certtool -s --load-privkey "$key" --outfile "$crt" --template "$crt_tmpl"
}
test -x ./PR-DNSd || go build .
test -x ./query || go build ./cmd/query
trap 'kill $pids' EXIT
./PR-DNSd -chroot "" -listen "" -tlslisten :8533 -cert "$crt" -key "$key" & pids="$!"
sleep 1
./query -netproto tcp-tls -server 127.0.0.1:8533 -capem $crt google.com. A
