#! /usr/bin/env python3
#  -------------------------------------------------------------------
#                   Intel Threat Match |  Mark Rodman
#  -------------------------------------------------------------------
#
#  ThreatMatch class is core of functionality.
#  It connects to the cluster, checks the cluster and performs searches
#  and aggregations.
#
#  --------------------------------------------------------------------

from elasticsearch import *
from itertools import count
import requests
import pprint


class TrafficIP(object):
    """ A class for each observed IP address """
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.checked = False
        self.pending_check = True
        self.known_bad = False
        self.ip_address_instance_counter = 1
        self.type = "external"

        # Check if internal
        if str(self.ip_address).startswith(("10.", "172.16.", "192.168.")):
            self.type = "internal"

    def set_pending_check(self):
        self.pending_check = True
        return

    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item,self.__dict__[item])
                                                       for item in self.__dict__))



class TrafficList(object):
    """ A class for a list of observed IP addresses """
    def __init__(self, name):
        self.name = name
        self.traffic_list = []

    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item,self.__dict__[item])
                                                       for item in self.__dict__))


class SearchResult(object):
    """ A class to handle results, not sure how this will work """
    """ At present it represents one search result item"""

    def __init__(self, result_data):
        self.result = result_data

    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item,self.__dict__[item])
                                                       for item in self.__dict__))


class ThreatMatch(object):
    """ A class to manage the threat match process """
    def __init__(self, name, e_cli_ip, e_cli_port, e_cli_proto):
        self.checked = 0
        self.check_counter = 0
        self.cluster_comms_response = 0
        self.name = name
        self.e_cli_ip = e_cli_ip
        self.e_cli_port = e_cli_port
        self.e_cli_proto = e_cli_proto
        self.e_cli_target = self.e_cli_proto + self.e_cli_ip + ":" + self.e_cli_port
        self.initial_status = 0
        self.es = ""
        self.e_health = {}
        self.last_query_result = {}
        self.agg_name = ""
        self.all_results = []                                                              # complete list of results
        self.agg_results = []

        if self.checked == 0:
            print("Initial creation, Connect not checked, now checking")
            self.cluster_comms_response = self.request_check()

        if self.checked == 1 and self.cluster_comms_response == 200:
            self.es = Elasticsearch([{'host': self.e_cli_ip, 'port': self.e_cli_port}])
            self.update_cluster_status()
        else:
            print("An error state was detected, response code: " + str(self.cluster_comms_response))

    def request_check(self):
        # method used to simply check comms with the Elastic node used for client operation,
        # without success nothing further can happen.
        if self.checked == 1:
            print("Recheck requested")
        res = requests.get(self.e_cli_target)
        if res.status_code != 200:
            print("Error connecting!!")
        print("Success: Connected to Elastic Client Node: " + self.e_cli_target)
        self.checked = 1
        self.check_counter = self.check_counter + 1
        return res.status_code

    def print_cluster_status(self):
        self.prettyout(self.e_health)
        return

    def update_cluster_status(self):
        self.e_health = (self.es.cluster.health())
        return

    def prettyout(self, my_data):
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(my_data)
        return

    def dict_parse(self, my_data):
        if "hits" in my_data.keys():
            search_hits = my_data['hits']['hits']
            for num, doc in enumerate(search_hits):
                print(num, '--,', doc)
                print('_id:', doc['_id'])

        if "aggregations" in my_data.keys():
            search_aggs = my_data['aggregations'][self.agg_name]['buckets']
            for num, doc in enumerate(search_aggs):
                self.agg_results.append(SearchResult(doc))
        return


    # basic_match_search is deprecated, use basic_search and set search type as match
    def basic_match_search(self, query_index, query_field, query_value, size):
        my_query_body = {
            "query": {
                "match": {
                    query_field: query_value
                }
            }
        }
        self.last_query_result = self.es.search(index=query_index, size=size, body=my_query_body)
        return self.last_query_result

    # basic_wildcard_search is deprecated, use basic_search and set search type as wildcard
    def basic_wildcard_search(self, query_index, query_field, query_value, size):
        my_query_body = {
            "query": {
                "wildcard": {
                    query_field: query_value
                }
            }
        }
        self.last_query_result = self.es.search(index=query_index, size=size, body=my_query_body)
        self.dict_parse(self.last_query_result)
        return self.last_query_result

    # Use instead of match or wildcard
    def basic_search(self, query_index, query_field, query_value, size, search_type):
        # requires search type to be set, either 'match' or 'wildcard'
        # valid search_types
        #       'match'
        #       'wildcard'
        # a match query will expect an explicit query_value
        # a wildcard query can use an value with *
        my_query_body = {
            "query": {
                search_type: {
                    query_field: query_value
                }
            }
        }
        self.last_query_result = self.es.search(index=query_index, size=size, body=my_query_body)
        self.dict_parse(self.last_query_result)
        return self.last_query_result

    def basic_agg_search(self, query_index, query_field, size, query_gte, query_lte, agg_name):
        self.agg_name = agg_name
        my_query_body = {
            "aggs": {
                self.agg_name: {
                    "terms": {
                        "field": query_field,
                        "size": size
                    }
                }
            },
            "stored_fields": [
                "*"
            ],

            "docvalue_fields": [
                {
                    "field": "timestamp",
                    "format": "date_time"
                },
                {
                    "field": "@timestamp",
                    "format": "date_time"
                }
            ],
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "format": "strict_date_optional_time",
                                    "gte": query_gte,
                                    "lte": query_lte
                                }
                            }
                        }
                    ],
                    "filter": [
                        {
                            "match_all": {}
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }
        self.last_query_result = self.es.search(index=query_index, body=my_query_body)
        self.dict_parse(self.last_query_result)
        return self.last_query_result

    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item,self.__dict__[item])
                                                       for item in self.__dict__))

