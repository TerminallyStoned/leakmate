# dns2tcp for the lab (card #8). Ubuntu packages dns2tcp 0.5.2, so there is nothing to
# build: /usr/bin/dns2tcpd (server) and /usr/bin/dns2tcpc (client).
#
# tcpdump is here because the capture of a DNS-tunnelled transfer has to be taken inside
# the network - the lab is internal and the tools' DNS bootstrap goes straight to the tool
# server, not through the card-5 resolver (see testbed/tools/docker-compose.yml).
# curl is used by run_tool.sh to push payload through the tunnel.
FROM ubuntu:resolute

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      dns2tcp tcpdump curl ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

COPY server.conf start.sh pull.py /opt/dns2tcp/
RUN chmod +x /opt/dns2tcp/start.sh
WORKDIR /out

EXPOSE 53/udp
CMD ["/opt/dns2tcp/start.sh"]
