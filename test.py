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


def basic_match_search(target, port, myindex, query_field, query_value):
    size = 10
    es = Elasticsearch([{'host': target, 'port': port}])

    my_query_body = {
        "query": {
            "match": {
                query_field: query_value
            }
        }
    }

    results = es.search(index=myindex, size=size, body=my_query_body)
    prettyout(results)
    return


def basic_wildcard_search(target, port, myindex, query_field, query_value):
    size = 10
    es = Elasticsearch([{'host': target, 'port': port}])

    my_query_body = {
        "query": {
            "wildcard": {
                query_field: query_value
            }
        }
    }

    results = es.search(index=myindex, size=size, body=my_query_body)
    prettyout(results)
    return


def basic_agg_search(target, port, myindex):
    size = 1
    es = Elasticsearch([{'host': target, 'port': port}])
    my_size = 1500
    my_field = "ip"
    my_query_body = {
        "aggs": {
            "2": {
                "terms": {
                    "field": my_field,
                    "size": my_size
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
                                "gte": "now-1m",
                                "lte": "now"
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

    results = es.search(index=myindex, body=my_query_body)
    prettyout(results)
    return





def main():
    cluster_status_code = check_client_requests(e_target)
    if cluster_status_code == 200:
        print("we connected checking health")
        check_health_es(e_client_ip, e_client_port)

        query_field = "ip"
        query_value = "*"
        query_index = "wazuh-monitoring-3.x-2019.12.28"
        #basic_wildcard_search(e_client_ip, e_client_port, query_index, query_field, query_value)
        basic_agg_search(e_client_ip, e_client_port, query_index)

    else:
        print("Exiting, we should sent a P1 alert")
        exit()


if __name__ == '__main__':
    main()