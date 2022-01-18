#!/usr/bin/env python

import re
import subprocess
import sys

GOOGLE_SPF_RECORD = "_spf.google.com"


def exit_error(message):
    sys.stderr.write("Error: {0}\n".format(message))
    sys.exit(1)


def exec_bin(command, *args):
    try:
        result = subprocess.check_output([command] + list(args))
    except subprocess.CalledProcessError:
        return False

    return result.strip()


class QuerySPF(object):
    SPF_RECORD_VALUE_REGEXP = re.compile(r'TXT[\t ]+"([^"]+)')

    def __init__(self, dig_path):
        self._dig_path = dig_path

    def query(self, hostname):
        # query TXT record via dig, extract record value
        result = exec_bin(self._dig_path, "+noall", "+answer", "TXT", hostname)
        if not result:
            return False

        match = QuerySPF.SPF_RECORD_VALUE_REGEXP.search(result)
        if not match:
            # no match
            return False

        # successfully extracted a record value
        return match.group(1).lower()


class GoogleApiCidrList(object):
    def __init__(self, query):
        self._query = query

    def _parse_spf_rule(self, rule):
        # build lists of SPF includes and CIDRs found
        include_list = set()
        cidr_list = set()

        for rule_part in rule.strip().split(" "):
            if rule_part.startswith("include:"):
                # extract hostname from [include:] rule
                include_list.add(rule_part[8:])

            elif rule_part.startswith("ip4:"):
                # save CIDR
                cidr_list.add(rule_part[4:])

        return (include_list, cidr_list)

    def cidr_list(self, start_spf_hostname):
        result_list = set()
        include_seen = set()

        # kick off querying, starting with [start_spf_hostname]
        queue = [start_spf_hostname]
        while queue:
            # shift SPF host item off queue
            query_hostname = queue[0]
            queue = queue[1:]

            rule = self._query.query(query_hostname)
            include_seen.add(query_hostname)

            if rule is not False:
                # extract includes and CIDRs from rule - add unseen includes to queue
                include_list, cidr_list = self._parse_spf_rule(rule)
                queue.extend(list(include_list - include_seen))

                # add CIDRs to collection
                result_list.update(cidr_list)

            else:
                exit_error("unable to query [{0}]".format(query_hostname))

        return sorted(result_list)


def main():
    # find path to dig
    dig_path = exec_bin("which", "dig")
    if dig_path is False:
        exit_error("unable to locate dig")

    # walk SPF record then list CIDRs extracted
    api_range = GoogleApiCidrList(QuerySPF(dig_path))
    for item in api_range.cidr_list(GOOGLE_SPF_RECORD):
        print(item)


if __name__ == "__main__":
    main()
