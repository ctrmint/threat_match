#! /usr/bin/env python3
#

from elasticsearch import *
from enviro import *
import requests
import pprint
import json


def prettyout(mydata):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(mydata)
    return


def check_client_requests(target):
    res = requests.get(target)
    if res.status_code != 200:
        print("Error connecting!!")

    print("Connected to Elastic Client Node: "+ target)
    return res.status_code


def check_health_es(target, port):
    pp = pprint.PrettyPrinter(indent=4)
    es = Elasticsearch([{'host': target, 'port': port}])
    e_health = (es.cluster.health())
    pp.pprint(e_health)
    if (e_health.get('status')).lower() != "green":
        print("\n !!! Warning cluster is not optimal, please seek review !!!")
        if (e_health.get('status')).lower() == "red":
            print("Cluster status is in the red, urgent")
        print(" !!! Status is :" + e_health.get('status') + "                                  !!!")


def basic_doc_search(target, port, myindex, query_field, query_value):
    es = Elasticsearch([{'host': target, 'port': port}])
    results = es.search(index=myindex, body={"query": {"match": {query_field: query_value}}})
    prettyout(results)
    return


def main():
    cluster_status_code = check_client_requests(e_target)
    if cluster_status_code == 200:
        print("we connected checking health")
        check_health_es(e_client_ip, e_client_port)

        query_field = "ip"
        query_value = "192.168.1.30"
        query_index = "wazuh-monitoring-3.x-2019.12.28"
        basic_doc_search(e_client_ip, e_client_port, query_index, query_field, query_value)

    else:
        print("Exiting, we should sent a P1 alert")
        exit()


if __name__ == '__main__':
    main()