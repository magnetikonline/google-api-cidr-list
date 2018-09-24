#!/usr/bin/env python

import os.path
import sys
import unittest

sys.path.insert(0,os.path.realpath(os.path.dirname(__file__) + '/..'))
import googleapicidrlist


class ScriptTest(unittest.TestCase):
	def test_api_range(self):
		api_range = googleapicidrlist.GoogleApiCidrList(TestQuerySPF())

		expected = [
			'cidr-01',
			'cidr-02',
			'cidr-03',
			'cidr-04',
			'cidr-05',
			'cidr-06',
			'cidr-07',
			'cidr-08',
			'cidr-09',
			'cidr-10'
		]

		self.assertEqual(
			api_range.cidr_list(googleapicidrlist.GOOGLE_SPF_RECORD),
			expected
		)

class TestQuerySPF(object):
	TEST_QUERY_HOSTNAME = {
		googleapicidrlist.GOOGLE_SPF_RECORD: 'v=spf1 include:one.host',
		'one.host': 'v=spf1 include:two.host include:three.host ~all',
		'two.host': 'v=spf1 include:four.host ip4:cidr-01 ip4:cidr-02 ip4:cidr-03 ~all',
		'three.host': 'v=spf1 include:one.host four.host ip4:cidr-04 ip4:cidr-05 ip4:cidr-06 ~all',
		'four.host': 'v=spf1 include:two.host include:five.host ip4:cidr-02 ip4:cidr-07 ip4:cidr-08 ~all',
		'five.host': 'v=spf1 ip4:cidr-09 ip4:cidr-10 ip4:cidr-01 ip4:cidr-04 ~all'
	}

	def query(self,hostname):
		return TestQuerySPF.TEST_QUERY_HOSTNAME[hostname]


if (__name__ == '__main__'):
	unittest.main()
