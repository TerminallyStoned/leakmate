#!/bin/sh
# dns2tcpd forwards to 127.0.0.1:8080 (server.conf), so the tunnel needs something behind
# that port. A stdlib HTTP server serving /out is enough: run_tool.sh PUTs nothing, it only
# needs a real TCP session to carry bytes through the DNS tunnel.
set -eu

python3 -m http.server 8080 --bind 127.0.0.1 --directory /out >/tmp/http.log 2>&1 &
exec dns2tcpd -F -f /opt/dns2tcp/server.conf
