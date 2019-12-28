#! /usr/bin/env python3
#


from elasticsearch import *
from enviro import *
import requests
import pprint
import json
from Threatmatch import *




def main():
    threat = Threat_match("ThreatCluster", e_client_ip, e_client_port, e_client_proto)
    # debug the class instance
    threat.update_cluster_status()
    print("\n")
    query_field = "ip"
    query_value = "192.168.1.88"
    query_index = "wazuh-monitoring-3.x-2019.12.28"
    query_gte = "now-900m"
    query_lte = "now"
    size = 34900
    #result = threat.basic_search(query_index, query_field, query_value, size, "match")

    result = threat.basic_agg_search(query_index, query_field, 10, query_gte, query_lte)

    #threat.prettyout(result)
    threat.dict_parse(result)
    # Debug - dump instance attributes
    #print(threat)


if __name__ == '__main__':
    main()