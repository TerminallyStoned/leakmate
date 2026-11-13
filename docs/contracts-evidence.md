# Shared contracts: evidence

Why each choice in [contracts.md](contracts.md) was made, and where every number comes from. You don't need this
page to use the contracts; read it when you want to know why a rule exists, or before proposing to change one.

## Why each choice was made

| choice | source | what it says |
|---|---|---|
| `ts` in epoch seconds, client address, qname, string qtype, integer rcode; response fields optional | Zeek `DNS::Info` record, https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html | `ts` is a `time`; `query`, `qtype_name`, `rcode`, `rtt` and `answers` are all `&optional`, so "no response seen" is a normal state and needs a defined value |
| qtype as a mnemonic string | Elastic Common Schema, DNS fields, https://www.elastic.co/docs/reference/ecs/ecs-dns | `dns.question.type` is a keyword such as `AAAA`; `dns.question.name` is the queried name |
| integer rcode, string type, client endpoint | OCSF 1.3.0 DNS Activity (class 4003), https://schema.ocsf.io/1.3.0/classes/dns_activity | `query.hostname` is required, `query.type` is a string, `rcode_id` is an integer, `src_endpoint` is the client |
| `TYPE<n>` for unmapped codes | RFC 3597 §5, https://rfc-editor.org/rfc/rfc3597 | unknown types are written as "TYPE" followed by the decimal type number |
| per-query rows labelled by tool | Palau et al., *DNS Tunneling: A Deep Learning based Lexicographical Detection Approach*, arXiv:2006.06122 | a CNN on the domain name only; tunnel queries from dnscat2, iodine and DNSExfiltrator labelled by attacker domain and run time |
| raw CIC fields and labels | Mahdavifar et al., *Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine Learning*, ICCNS 2021; dataset page https://www.unb.ca/cic/datasets/dns-exf-2021.html | PCAPs plus per-packet CSV features, labelled by timestamp. Their split is a shuffled 70/30, which experiment S measures. |
| query name, response and record type as inputs; time-based training | Nadler, Aminov & Shabtai, *Detection of malicious and low throughput data exfiltration over the DNS protocol*, Computers & Security 80, 2019, arXiv:1709.08395 | per-domain features over 60-minute collection sets; trained on the first day of traffic, tested on the rest |
| time and session splits, never shuffled rows | Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022; Pendlebury et al., *TESSERACT*, USENIX Security 2019 | mixing past and future samples ("temporal snooping") overestimates detectors; respect time when splitting |
| `split` and `config` in every results record | Kapoor & Narayanan, *Leakage and the reproducibility crisis in machine-learning-based science*, Patterns 4(9), 2023 | eight kinds of leakage; record how data was split and prepared ("model info sheets") |
| group-aware splits need a group column | scikit-learn `model_selection`, https://scikit-learn.org/stable/api/sklearn.model_selection.html | `GroupKFold` keeps each group on one side; `TimeSeriesSplit` respects time but ignores groups |
| session = 30 min of inactivity | Google Analytics help, *About Analytics sessions*, https://support.google.com/analytics/answer/2731565 | a session lasts until 30 minutes of inactivity, the most widely used session rule |
| why not a flow id (Zeek `uid`, Community ID) | Community ID spec, https://github.com/corelight/community-id-spec; RFC 5452, https://www.rfc-editor.org/rfc/rfc5452 | both identify a 5-tuple including ports; resolvers randomise the source port per query, so for UDP DNS a flow is about one query |
| a live tunnel never idles for 30 min | iodine(8), https://www.mankier.com/8/iodine | `-I` defaults to 4 s; iodined drops a client after 60 s idle |
| `throttle` in milliseconds | DNSExfiltrator README, https://github.com/Arno0x/DNSExfiltrator; dnscat2 client docs, https://www.kali.org/tools/dnscat2 | `throttleTime` is "the time in milliseconds to wait between each DNS request"; dnscat2 `--delay <ms>` defaults to 1000 |

## Where every number comes from

### Contract figures

| figure | where used | source |
|---|---|---|
| `ts` range 0 ≤ ts < 2³² | validator | pcap packet records store "a 32-bit unsigned integer" of seconds since 1970-01-01 (draft-ietf-opsawg-pcap, https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-05.html). Any epoch time in milliseconds after 19 Feb 1970 exceeds 2³², so the check also catches ms. |
| `rcode` 0–15 | validator | the header RCODE is a 4-bit field (RFC 1035 §4.1.1, https://www.rfc-editor.org/rfc/rfc1035; RFC 6891). Codes above 15 exist only through EDNS. The extractor reads the 4-bit field. |
| `rcode` 3 = NXDOMAIN | sample | IANA DNS RCODE registry, https://www.iana.org/assignments/dns-parameters |
| `resp_size` 0 = no response | contract | a DNS message always has a 12-octet header (RFC 1035 §4.1.1), so a real response is never 0 bytes |
| qtype codes A=1, NS=2, CNAME=5, SOA=6, NULL=10, PTR=12, MX=15, TXT=16, AAAA=28, SRV=33, SVCB=64, HTTPS=65, ANY=255 | `qtype_name` | IANA RR TYPEs registry, https://www.iana.org/assignments/dns-parameters |
| `TYPE<n>` | `qtype_name` | RFC 3597 §5 |
| session idle gap 1800 s | `assign_sessions` | the Google Analytics session rule, 30 minutes of inactivity (https://support.google.com/analytics/answer/2731565). **No DNS or network-security source defines a session idle gap**; this rule comes from web analytics, chosen because it is the most widely used session definition. It is safely longer than tool keep-alives: iodine pings at most every 4 s and iodined drops a client after 60 s idle (iodine(8)). |
| `throttle` in ms | contract | DNSExfiltrator `throttleTime` is "the time in milliseconds to wait between each DNS request"; dnscat2 `--delay <ms>` |
| 70/30 train/test | extractor `--train-frac`, sample | CIC-Bell-DNS-EXF-2021's own evaluation uses a 70%/30% split (UNB dataset page). We keep the ratio but cut by time. |

### Synthetic-sample figures (`scripts/make_synthetic_sample.py`, testing only)

| figure | source |
|---|---|
| 1,000 rows | the contracts Trello card ("ship a 1,000-row sample file") |
| tunnel share 0.3705 | CIC-Bell-DNS-EXF-2021 sample counts: (53,978 light + 323,698 heavy) / 1,019,318 total (UNB dataset page) |
| benign qtypes A 61.5 %, PTR 27.2 %, MX 5.2 %, ANY 4.6 % (renormalised) | Jung, Sit, Balakrishnan & Morris, *DNS performance and the effectiveness of caching*, IEEE/ACM ToN 10(5), 2002, Table II, mit-dec00 trace |
| benign lookups: 23 % no answer, 13 % negative answer (NXDOMAIN) | Jung et al. 2002, §I, mit-dec00 ("23% of all client lookups … fail to elicit any answer … 13% … indicates an error. Most … the desired name does not exist") |
| domain popularity Zipf α = 1.11378 | Jung et al. 2002, Fig. 8(b): fitted popularity index for second-level domains, mit-dec00 |
| PTR names `d.c.b.10.in-addr.arpa` | RFC 1035 §3.5 (IN-ADDR.ARPA) |
| hosts in 10.0.0.0/8 | RFC 1918 private address space |
| attacker domain `tunnel.test` | the testbed zone `testbed/attacker-ns/db.tunnel.test`; `.test` is reserved for testing by RFC 2606 |
| label ≤ 63, name ≤ 255 octets on the wire (253 characters) | RFC 1035 §2.3.4 |
| query size = 12 + (len(qname) + 2) + 4 | RFC 1035 §4.1.1 header (12), §3.1 name encoding (+2), §4.1.2 QTYPE + QCLASS (2 + 2) |
| answer size = query + 2 (name pointer) + 10 (TYPE, CLASS, TTL, RDLENGTH) + RDATA | RFC 1035 §3.2.1, §4.1.4. RDATA uses the smallest valid value per type: A 4, AAAA 16 (RFC 3596), TXT 1 (empty string), NULL 0, PTR/CNAME a name, MX 2 + a name (§3.3). Negative answers are header + question only, the no-SOA form RFC 2308 allows for non-authoritative replies. |
| iodine: base32, NULL, names filled to 255 octets | iodine README: Base32 "is used when autodetection fails"; NULL is first in the autodetect bandwidth order (iodine(8)); "hostnames are normally used up to their maximum length, 255 characters" |
| dnscat2: hex, 60-character labels, 110 data bytes, qtype chosen at random from TXT, CNAME, MX | dnscat2 `doc/protocol.md` (hex); client `tunnel_drivers/driver_dns.c` (`MAX_FIELD_LENGTH 62`, `MAX_DNSCAT_LENGTH`, `rand() % type_count`) and `driver_dns.h` (`DEFAULT_TYPES "TXT,CNAME,MX"`) |
| dns2tcp: base64, TXT, names ≤ 200 characters | dns2tcp `client/options.c` (default TXT), `client/requests.c` (base64), `common/includes/dns.h` (`MAX_HOST_NAME_ENCODED 200`) |
| DNSExfiltrator: base64url, TXT, `<chunk>.<63-char labels>.<domain>`, 255-byte requests | `dnsExfiltrator.cs`: `DNS_TYPE_TXT`, `requestMaxSize = 255`, `labelMaxSize = 63`, chunk-size formula, `throttleTime = 0` |

### Figures with no source

These are test-fixture values. They don't change what the contract allows, so pick anything that keeps the sample valid:
- the start time (epoch 1,700,000,000)
- the overall query rate (Poisson, 5 per second): no measurement study we found reports a per-host DNS query rate
- 39 benign hosts
- the random seed
- the 30-domain fallback list used without `--tranco`. It is real domains but not ranked from a source, so pass `--tranco` for real ranks.

Tunnel downstream payload sizes are not modelled; answers use the smallest valid RDATA.
