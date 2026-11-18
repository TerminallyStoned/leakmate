# Image for the live sniffer inside the testbed. Built by live/run_live.sh, which passes a build
# context holding only the two requirements files; the repo itself is mounted at /repo at run time.
FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-m1.txt requirements-live.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-m1.txt -r /tmp/requirements-live.txt
WORKDIR /repo
ENV PYTHONPATH=/repo PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "live"]
