FROM ubuntu:24.04

# dnsutils = dig/nslookup for testing resolution and the containment proof.
# Installed at BUILD time (build has internet); at RUN time the victim is on an
# internal-only network with no route out.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dnsutils iputils-ping curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
