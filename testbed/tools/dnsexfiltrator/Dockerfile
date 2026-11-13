# DNSExfiltrator receiver + sender for the lab (card #8).
#
# Both roles ship in one image: `command` in docker-compose.yml picks server or client.
# The upstream project is Arno0x/DNSExfiltrator: its Windows client cannot run on Linux
# (see client.py), so the client here reproduces its exact wire format, and the server is
# a Python 3 port of the upstream Python 2 `dnsexfiltrator.py`.
FROM python:3.12-slim

# tcpdump so a capture run can record the tunnel from inside this container: the lab is
# internal, and the clients resolve the tool server directly, so the resolver's pcap does
# not see this traffic (see docker-compose.yml).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "dnslib==0.9.25"

WORKDIR /opt/dnsexfiltrator
COPY server.py client.py ./

# The receiver is authoritative for the exfil zone, so nothing else can answer for it.
EXPOSE 53/udp
ENTRYPOINT []
CMD ["python3", "server.py", "--help"]
