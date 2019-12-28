#! /usr/bin/env python3
#

from elasticsearch import *
from enviro import *
import requests
import pprint
import json


class Threat_match(object):
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


    def basic_match_search(self, query_index, query_field, query_value, size):
        my_query_body = {
            "query": {
                "match": {
                    query_field: query_value
                }
            }
        }
        results = self.es.search(index=query_index, size=size, body=my_query_body)
        self.prettyout(results)
        return results



    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item,self.__dict__[item])
                                                       for item in self.__dict__))

