# Benign traffic host (Trello card 7). One container == one src_host in the sidecar;
# scale it with run_benign.sh --docker --hosts N to get distinct source IPs.
FROM python:3.12-slim

# dig gives per-lookup rcode + response size; curl and apt are the "normal tools" whose
# lookups must appear in the capture, so they are installed for real, not simulated.
# Runs as root so `apt-get update` / `--download-only` behave like a real workstation;
# the container is only ever attached to the isolated testbed network.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Headless-browser page views are optional and heavy (~400 MB):
#   docker build --build-arg WITH_BROWSER=1 -t leakmate-benign .
ARG WITH_BROWSER=0
RUN if [ "$WITH_BROWSER" = "1" ]; then pip install --no-cache-dir "playwright==1.48.0" \
      && playwright install --with-deps chromium; fi

WORKDIR /app
COPY domains.py generate.py check_benign.py fallback_domains.txt ./

ENTRYPOINT ["python3", "generate.py"]
CMD ["--minutes", "10", "--target-qps", "10", "--out", "/out"]
