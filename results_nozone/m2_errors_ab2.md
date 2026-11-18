# M2 error analysis (`--root data/processed_nozone`)

## m2_ablation2_sup / E1

Threshold -6.5913; missed tunnels 3 of 34180; false positives in the top 15 domains: 693.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| ajax.masked.domain | 609 | -6.591 |
| miit.masked.domain | 9 | -6.556 |
| rubiconproject.masked.domain | 2 | -6.103 |
| 6tveo52orpggc2e3q7ae.masked.domain | 2 | -6.131 |
| drfeung56x.masked.domain | 2 | -6.408 |
| fq4f2om7r34azp2pau5i.masked.domain | 2 | -6.420 |
| avast.masked.domain | 2 | -6.483 |
| phaorypavb4skr23q.storage.masked.domain | 2 | -6.548 |
| 3gppnetwork.masked.domain | 2 | -6.558 |
| www.miit.masked.domain | 2 | -6.578 |
| dsabqyutzqedg.masked.domain | 1 | 5.801 |
| c601c9eb.masked.domain | 1 | 4.502 |
| ddjvkretyzs.masked.domain | 1 | 2.778 |
| deviantart.masked.domain | 1 | -5.006 |
| ayqie7glc3h3cb3ar4d7.masked.domain | 1 | -5.108 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 693 | 69 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dns2tcp | 7764 | 0 | 1.000 |
| dnscat2 | 6182 | 0 | 1.000 |
| dnsexfiltrator | 9402 | 0 | 1.000 |
| iodine | 10832 | 3 | 1.000 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 10512 | 3 | 1.000 |
| 31–60 | 524 | 0 | 1.000 |
| 61–100 | 642 | 0 | 1.000 |
| 101–150 | 2165 | 0 | 1.000 |
| 151–200 | 524 | 0 | 1.000 |
| >200 | 19813 | 0 | 1.000 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| iodine | pabqej4y.masked.domain | 22 | -6.735 |
| iodine | pabqej2y.masked.domain | 22 | -6.734 |
| iodine | pabqej0y.masked.domain | 22 | -6.730 |

## m2_ablation2_sup / E3_dns2tcp

Threshold -6.0678; missed tunnels 7417 of 7764; false positives in the top 15 domains: 16503.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| masked.domain | 16482 | -6.068 |
| dsabqyutzqedg.masked.domain | 1 | 5.533 |
| ddjvkretyzs.masked.domain | 1 | 1.722 |
| craigslist.masked.domain | 1 | 0.058 |
| c4ab935c.masked.domain | 1 | -0.165 |
| a6500ec50.masked.domain | 1 | -1.250 |
| c601c9eb.masked.domain | 1 | -4.482 |
| ailawandorder.masked.domain | 1 | -5.663 |
| cootlogix.masked.domain | 1 | -5.672 |
| c75572c8.masked.domain | 1 | -5.693 |
| deviantart.masked.domain | 1 | -5.731 |
| dnykmcubsx.masked.domain | 1 | -5.773 |
| s1a8155a1.masked.domain | 1 | -5.779 |
| c8518c85.masked.domain | 1 | -5.798 |
| c46fda7ad.masked.domain | 1 | -5.815 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 16503 | 22 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dns2tcp | 7764 | 7417 | 0.045 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 7764 | 7417 | 0.045 |
| 31–60 | 0 | 0 |  |
| 61–100 | 0 | 0 |  |
| 101–150 | 0 | 0 |  |
| 151–200 | 0 | 0 |  |
| >200 | 0 | 0 |  |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| dns2tcp | Af8O6w7wBA.masked.domain | 24 | -6.411 |
| dns2tcp | Af8LngujBA.masked.domain | 24 | -6.411 |
| dns2tcp | Af8N6g3vBA.masked.domain | 24 | -6.411 |

## m2_ablation2_sup / E3_dnscat2

Threshold -6.3635; missed tunnels 1424 of 6182; false positives in the top 15 domains: 78.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| rakuten.masked.domain | 23 | -6.333 |
| rubiconproject.masked.domain | 2 | -6.354 |
| gtld-servers.masked.domain | 2 | -6.355 |
| dsabqyutzqedg.masked.domain | 1 | 5.857 |
| ddjvkretyzs.masked.domain | 1 | 5.402 |
| c4ab935c.masked.domain | 1 | -2.448 |
| gdpd6oy2pwowosvosr.masked.domain | 1 | -3.613 |
| dqw3acqyjj.masked.domain | 1 | -4.767 |
| s1a8155a1.masked.domain | 1 | -5.402 |
| telecid.masked.domain | 1 | -5.716 |
| cootlogix.masked.domain | 1 | -5.722 |
| 16ab3f8fbf11be.masked.domain | 1 | -5.980 |
| denofqt7vc.masked.domain | 1 | -6.007 |
| deviantart.masked.domain | 1 | -6.043 |
| c601c9eb.masked.domain | 1 | -6.044 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 78 | 54 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dnscat2 | 6182 | 1424 | 0.770 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 0 | 0 |  |
| 31–60 | 523 | 521 | 0.004 |
| 61–100 | 105 | 99 | 0.057 |
| 101–150 | 54 | 16 | 0.704 |
| 151–200 | 33 | 5 | 0.848 |
| >200 | 5467 | 783 | 0.857 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| dnscat2 | 6ed701447f4dc64b720452006995b60b52.masked.domain | 48 | -6.506 |
| dnscat2 | 833b012b7a9bc64599fae22d5f8ff2a8ba.masked.domain | 48 | -6.506 |
| dnscat2 | f0c901d4b31f7b78a4c86b002bff070e9f.masked.domain | 48 | -6.505 |

## m2_ablation2_sup / E3_dnsexfiltrator

Threshold -6.2118; missed tunnels 0 of 9402; false positives in the top 15 domains: 79.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| 6tveo52orpggc2e3q7ae.masked.domain | 2 | -5.697 |
| drfeung56x.masked.domain | 2 | -6.106 |
| 2ywes5faomrl75pv.masked.domain | 2 | -6.106 |
| gosuslugi.masked.domain | 2 | -6.141 |
| rubiconproject.masked.domain | 2 | -6.157 |
| fq4f2om7r34azp2pau5i.masked.domain | 2 | -6.182 |
| 1b007d3531d21606.masked.domain | 2 | -6.184 |
| dsabqyutzqedg.masked.domain | 1 | 5.947 |
| ddjvkretyzs.masked.domain | 1 | 4.644 |
| s1a8155a1.masked.domain | 1 | -1.987 |
| c4ab935c.masked.domain | 1 | -2.076 |
| a6500ec50.masked.domain | 1 | -2.901 |
| c601c9eb.masked.domain | 1 | -3.053 |
| gdpd6oy2pwowosvosr.masked.domain | 1 | -4.024 |
| pki.masked.domain | 1 | -5.197 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 79 | 72 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| dnsexfiltrator | 9402 | 0 | 1.000 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 0 | 0 |  |
| 31–60 | 0 | 0 |  |
| 61–100 | 3 | 0 | 1.000 |
| 101–150 | 4 | 0 | 1.000 |
| 151–200 | 4 | 0 | 1.000 |
| >200 | 9391 | 0 | 1.000 |

### fn_examples

_none_

## m2_ablation2_sup / E3_iodine

Threshold -6.0938; missed tunnels 2748 of 10832; false positives in the top 15 domains: 48.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| 1b007d3531d21606.masked.domain | 2 | -5.443 |
| 2ywes5faomrl75pv.masked.domain | 2 | -5.624 |
| 6tveo52orpggc2e3q7ae.masked.domain | 2 | -5.911 |
| m5f7mloayhzfzrlxql.masked.domain | 2 | -5.993 |
| fq4f2om7r34azp2pau5i.masked.domain | 2 | -6.051 |
| e24c0c6a9d68c0ff.masked.domain | 2 | -6.051 |
| d81b32396f5c8b22.masked.domain | 2 | -6.075 |
| b93b1a0f290605d0.masked.domain | 1 | -2.918 |
| gdpd6oy2pwowosvosr.masked.domain | 1 | -5.080 |
| 33p776xqw3kkdmvlfz57.masked.domain | 1 | -5.392 |
| b7c01f0fb397a75f.masked.domain | 1 | -5.650 |
| 58b85fc68b1846e2.masked.domain | 1 | -5.754 |
| v5b7zghues3odjqdrq5.masked.domain | 1 | -5.853 |
| 461ae70c1608b752.masked.domain | 1 | -5.887 |
| a7b6db80c6a0182b.masked.domain | 1 | -5.890 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 48 | 41 |

### fn_by_tool

| tool | rows | missed | recall |
|---|---|---|---|
| iodine | 10832 | 2748 | 0.746 |

### fn_by_length

| length | rows | missed | recall |
|---|---|---|---|
| ≤30 | 2748 | 2748 | 0.000 |
| 31–60 | 1 | 0 | 1.000 |
| 61–100 | 534 | 0 | 1.000 |
| 101–150 | 2107 | 0 | 1.000 |
| 151–200 | 487 | 0 | 1.000 |
| >200 | 4955 | 0 | 1.000 |

### fn_examples

| tool | qname | length | score |
|---|---|---|---|
| iodine | paaaei3i.masked.domain | 22 | -6.221 |
| iodine | pabyei3a.masked.domain | 22 | -6.221 |
| iodine | paaieh1q.masked.domain | 22 | -6.221 |

## m2_ablation2_sup / E5

Threshold -6.5653; missed tunnels 0 of 457; false positives in the top 15 domains: 78.

### fp_by_name

| qname | count | max_score |
|---|---|---|
| 6tveo52orpggc2e3q7ae.masked.domain | 2 | -6.320 |
| rubiconproject.masked.domain | 2 | -6.442 |
| fq4f2om7r34azp2pau5i.masked.domain | 2 | -6.498 |
| phaorypavb4skr23q.storage.masked.domain | 2 | -6.500 |
| drfeung56x.masked.domain | 2 | -6.505 |
| avast.masked.domain | 2 | -6.534 |
| gosuslugi.masked.domain | 2 | -6.537 |
| 2ywes5faomrl75pv.masked.domain | 2 | -6.553 |
| dsabqyutzqedg.masked.domain | 1 | 5.688 |
| ddjvkretyzs.masked.domain | 1 | 4.289 |
| c601c9eb.masked.domain | 1 | 1.737 |
| c4ab935c.masked.domain | 1 | -3.531 |
| pki.masked.domain | 1 | -4.687 |
| s1a8155a1.masked.domain | 1 | -5.349 |
| a6500ec50.masked.domain | 1 | -5.570 |

### fp_by_domain

| domain | count | distinct_names |
|---|---|---|
| masked.domain | 78 | 70 |

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
