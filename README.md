# Google API CIDR list

Script to generate a current list of CIDR ranges covering public [Google APIs and services](https://developers.google.com/apis-explorer/), such as Bigtable, Pub/Sub and Cloud Storage. IPv4 addresses are extracted from TXT record `_spf.google.com` as outlined by Google Cloud Platform [VPC documentation](https://cloud.google.com/vpc/docs/configure-private-google-access#dns_resolution).

- [Overview](#overview)
- [Usage](#usage)
- [Tests](#tests)

## Overview

The DNS record is walked recursively, following `include:` directives - although at time of writing (September 2018) the SPF rules only run two records deep. For simplicity DNS queries are performed by calls to [`dig`](https://linux.die.net/man/1/dig).

Practical uses for this list:

- Define route tables allowing GCP instances without public IP addresses access to the Internet via a [NAT gateway](https://cloud.google.com/vpc/docs/special-configurations#natgateway) _plus_ optimized Google API access through [private VPC access](https://cloud.google.com/vpc/docs/configure-private-google-access#requirements).
- Firewall rules to allow only instance egress to Google APIs.

## Usage

```sh
$ ./googleapicidrlist.py
108.177.8.0/21
108.177.96.0/19
130.211.0.0/22
172.217.0.0/19
...
```

## Tests

Tests via [`test/googleapicidrlist.py`](test/googleapicidrlist.py).
