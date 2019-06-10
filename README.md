# PR-DNSd

Passive-Recursive DNS daemon.

## Quickstart

```sh
go get github.com/korc/PR-DNSd
sudo setcap cap_net_bind_service,cap_sys_chroot=ep go/bin/PR-DNSd
go/bin/PR-DNSd -upstream 9.9.9.9:53 -listen 127.0.0.1:53
echo nameserver 127.0.0.1 | sudo tee /etc/resolv.conf
dig google.com
dig -x $(dig +short google.com)
```

_If you can't use `setcap`, you have to use `-chroot ""` and `-listen :<high_port>` options, or run as `root`._

## Options

```
-cert string
    TCP-TLS listener certificate (required for tls listener)
-chroot string
    chroot to directory after start (default "/var/tmp")
-count int
    Count of replies allowed before debounce delay is applied (default 10)
-ctmout string
    Client timeout for upstream queries
-debounce string
    Required time duration between UDP replies to single IP to prevent DoS (default "200ms")
-key string
    TCP-TLS certificate key (default same as -cert value)
-listen string
    listen address (default ":53")
-silent
    Don't report normal data
-store string
    Store PTR data to specified file
-tlslisten string
    TCP-TLS listener address (default ":853")
-upstream string
    upstream DNS server (default "1.1.1.1:53")
```
