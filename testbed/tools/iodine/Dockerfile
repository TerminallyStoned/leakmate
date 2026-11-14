FROM ubuntu:24.04

# iodine (iodined server + iodine client) plus small helpers for pushing and
# pacing test data through the tunnel. Built with internet; runs offline.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iodine iproute2 iputils-ping netcat-openbsd pv ca-certificates \
        tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
