# M2 error analysis (`--root data/processed_nozone`)

## m2 / E1

Threshold 5.6740; missed tunnels 3770 of 34180; false positives in the top 15 domains: 278.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| img-prod-cms-rt-microsoft-com.masked.domain | 277 | 5.685 |
| 64fz52su2k65naslgjsi.masked.domain | 1 | 5.993 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 278 | 2 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dns2tcp | 7764 | 1002 | 0.871 |
| dnscat2 | 6182 | 20 | 0.997 |
| dnsexfiltrator | 9402 | 0 | 1.000 |
| iodine | 10832 | 2748 | 0.746 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 10512 | 3750 | 0.643 |
| 31–60 | 524 | 20 | 0.962 |
| 61–100 | 642 | 0 | 1.000 |
| 101–150 | 2165 | 0 | 1.000 |
| 151–200 | 524 | 0 | 1.000 |
| >200 | 19813 | 0 | 1.000 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| iodine | paayessa.masked.domain | 22 | 2.816 |
| iodine | paayeroa.masked.domain | 22 | 2.847 |
| iodine | paaaob5q.masked.domain | 22 | 2.862 |
| dns2tcp | Af8O7g7zBA.masked.domain | 24 | 4.865 |
| dns2tcp | Af8O2g7fBA.masked.domain | 24 | 4.884 |
| dns2tcp | Af8O1g7bBA.masked.domain | 24 | 4.917 |
| dnscat2 | 3f7c0121b896df7f620d0201ce29e0b4f0.masked.domain | 48 | 5.224 |
| dnscat2 | d8f8015b0c5e9ca851d28c009197f12179.masked.domain | 48 | 5.339 |
| dnscat2 | 86fb015b0cd799c7f9ed7a00a10f77596a.masked.domain | 48 | 5.405 |

## m2_hostavg / E1

Threshold 2.8352; missed tunnels 0 of 34180; false positives in the top 15 domains: 65.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| masked.domain | 23 | 3.292 |
| www.masked.domain | 4 | 3.155 |
| d7umqicpi7263.masked.domain | 3 | 3.243 |
| d1le29qyzha1u4.masked.domain | 3 | 3.112 |
| statics-marketingsites-wcus-ms-com.masked.domain | 3 | 2.852 |
| dftu77xade0tc.masked.domain | 2 | 3.228 |
| d2cpw7vd6a2efr.masked.domain | 2 | 3.001 |
| spot-price.s3.masked.domain | 2 | 2.852 |
| d1oqpvwii7b6rh.masked.domain | 2 | 2.850 |
| d3h2ozso0dirfl.masked.domain | 1 | 3.348 |
| 80c9968334697b.blob.core.masked.domain | 1 | 3.279 |
| d3ctxlq1ktw2nl.masked.domain | 1 | 3.235 |
| d1hemuljm71t2j.masked.domain | 1 | 3.164 |
| d1d1et6laiqoh9.masked.domain | 1 | 3.075 |
| awsmedia.s3.masked.domain | 1 | 3.061 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 65 | 30 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dns2tcp | 7764 | 0 | 1.000 |
| dnscat2 | 6182 | 0 | 1.000 |
| dnsexfiltrator | 9402 | 0 | 1.000 |
| iodine | 10832 | 0 | 1.000 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 10512 | 0 | 1.000 |
| 31–60 | 524 | 0 | 1.000 |
| 61–100 | 642 | 0 | 1.000 |
| 101–150 | 2165 | 0 | 1.000 |
| 151–200 | 524 | 0 | 1.000 |
| >200 | 19813 | 0 | 1.000 |

### fn_examples

_none_

## m2 / E5

Threshold 5.6740; missed tunnels 195 of 457; false positives in the top 15 domains: 278.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| img-prod-cms-rt-microsoft-com.masked.domain | 277 | 5.685 |
| 64fz52su2k65naslgjsi.masked.domain | 1 | 5.993 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 278 | 2 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dnscat2 | 118 | 1 | 0.992 |
| dnsexfiltrator | 68 | 0 | 1.000 |
| iodine | 271 | 194 | 0.284 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 194 | 194 | 0.000 |
| 31–60 | 14 | 1 | 0.929 |
| 61–100 | 27 | 0 | 1.000 |
| 101–150 | 78 | 0 | 1.000 |
| 151–200 | 10 | 0 | 1.000 |
| >200 | 134 | 0 | 1.000 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| iodine | pabip11a.masked.domain | 22 | 3.021 |
| iodine | pabip13a.masked.domain | 22 | 3.039 |
| iodine | pabah0fq.masked.domain | 22 | 3.090 |
| dnscat2 | 5e2701fe0b94edd5edea8b00186d579fa5.masked.domain | 48 | 5.589 |

## m2_hostavg / E5

Threshold 2.8352; missed tunnels 0 of 457; false positives in the top 15 domains: 65.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| masked.domain | 23 | 3.292 |
| www.masked.domain | 4 | 3.155 |
| d7umqicpi7263.masked.domain | 3 | 3.243 |
| d1le29qyzha1u4.masked.domain | 3 | 3.112 |
| statics-marketingsites-wcus-ms-com.masked.domain | 3 | 2.852 |
| dftu77xade0tc.masked.domain | 2 | 3.228 |
| d2cpw7vd6a2efr.masked.domain | 2 | 3.001 |
| spot-price.s3.masked.domain | 2 | 2.852 |
| d1oqpvwii7b6rh.masked.domain | 2 | 2.850 |
| d3h2ozso0dirfl.masked.domain | 1 | 3.348 |
| 80c9968334697b.blob.core.masked.domain | 1 | 3.279 |
| d3ctxlq1ktw2nl.masked.domain | 1 | 3.235 |
| d1hemuljm71t2j.masked.domain | 1 | 3.164 |
| d1d1et6laiqoh9.masked.domain | 1 | 3.075 |
| awsmedia.s3.masked.domain | 1 | 3.061 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 65 | 30 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dnscat2 | 118 | 0 | 1.000 |
| dnsexfiltrator | 68 | 0 | 1.000 |
| iodine | 271 | 0 | 1.000 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 194 | 0 | 1.000 |
| 31–60 | 14 | 0 | 1.000 |
| 61–100 | 27 | 0 | 1.000 |
| 101–150 | 78 | 0 | 1.000 |
| 151–200 | 10 | 0 | 1.000 |
| >200 | 134 | 0 | 1.000 |

### fn_examples

_none_

## m2_ablation1_char / E1

Threshold 2.9918; missed tunnels 9003 of 34180; false positives in the top 15 domains: 277.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| img-prod-cms-rt-microsoft-com.masked.domain | 277 | 3.081 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 277 | 1 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dns2tcp | 7764 | 6036 | 0.223 |
| dnscat2 | 6182 | 219 | 0.965 |
| dnsexfiltrator | 9402 | 0 | 1.000 |
| iodine | 10832 | 2748 | 0.746 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 10512 | 8784 | 0.164 |
| 31–60 | 524 | 0 | 1.000 |
| 61–100 | 642 | 2 | 0.997 |
| 101–150 | 2165 | 6 | 0.997 |
| 151–200 | 524 | 1 | 0.998 |
| >200 | 19813 | 210 | 0.989 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| iodine | pabaequi.masked.domain | 22 | 1.053 |
| iodine | pabyobli.masked.domain | 22 | 1.068 |
| iodine | pabaguma.masked.domain | 22 | 1.071 |
| dns2tcp | Af8Nbw10BA.masked.domain | 24 | 2.089 |
| dns2tcp | Af8O7w70BA.masked.domain | 24 | 2.092 |
| dns2tcp | Af8N7w30BA.masked.domain | 24 | 2.095 |
| dnscat2 | 7585012b7af4bb14885ed72636f60b43a07d83a3632dc4df7747da5cb918.ae7ae6a820c9bf95584aaf77a0067f43bde78ddfe13e540bf5210712a194.e45e195c5a617de790a1f07a2682b2deb324f9036f2daf91977bbf287c5f.d47d36f6dfcbd21178b6e7633d4a0ca4e4f8.masked.domain | 233 | 2.886 |
| dnscat2 | 23fc0174bcc69943a18f6b0a8458ff67f39d50bd1c79e90e670648a768d1.f704d86d8ad3f140e2b7f7b3fdf210a971119f9b54d5a543337a89f418e2.479dbccf9cd519e39ae5b3fa65d30204178dccd9e67e9e60f66b6917b43f.21fee9705930a74551aa6d2b2409fcc0111e.masked.domain | 233 | 2.914 |
| dnscat2 | 647b01cb70381b1c76fff50002f63f9bd0dd64ce3592aae49bdc498cb693.fc090e9a2d50e53c816e50ee78cf399dacf64c75a5034fce449a.masked.domain | 127 | 2.915 |
