# dnscat2 = Ruby server + C client (github.com/iagox86/dnscat2).
# Ubuntu 20.04 ships Ruby 2.7 (dnscat2 breaks on Ruby 3.x) AND its apt archive
# still resolves, unlike the EOL Debian base under ruby:2.7-slim.
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Install bundler from apt (its 2.x uses the modern compact index; the gem
# client shipped with Ruby 2.7 can't fetch from rubygems.org any more).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential git ca-certificates make libssl-dev bundler \
        tcpdump procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 https://github.com/iagox86/dnscat2.git

# Server gems (apt's bundler; ignore the lock's pinned bundler version)
WORKDIR /opt/dnscat2/server
RUN bundle install || (rm -f Gemfile.lock && bundle install)

# C client
WORKDIR /opt/dnscat2/client
RUN make

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /opt/dnscat2
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
