#!/bin/sh
# Zeek's dns.log for each pcap in /out/zeek_list.tsv (written by external_baselines.py zeek-list).
#   docker run --rm -v "$PWD/data/raw:/raw:ro" -v "$PWD/work/zeek:/out" zeek/zeek:latest sh /out/zeek_run.sh
set -e
n=0
while IFS="$(printf '\t')" read -r rel src; do
  [ -z "$rel" ] && continue
  n=$((n + 1))
  dir="/out/$(echo "$src" | tr '/' '_' | sed 's/\.pcap.*$//')"
  mkdir -p "$dir"
  cd "$dir"
  zeek -C -r "/raw/$rel" >/dev/null 2>zeek.err || echo "FAIL $rel"
  find . -maxdepth 1 -name '*.log' ! -name dns.log -delete
  printf '%s\t%s\n' "$rel" "$src" > source.txt
done < /out/zeek_list.tsv
echo "processed $n"
