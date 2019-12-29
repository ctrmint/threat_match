#! /usr/bin/env python3
#

from elasticsearch import *
from enviro import *
from Threatmatch import *


def main():
    observed_traffic = TrafficList("traffic")
    inspected_data = ThreatMatch("ThreatCluster", e_client_ip, e_client_port, e_client_proto)
    # debug the class instance
    inspected_data.update_cluster_status()
    print("\n")
    query_field = "ip"
    query_value = "192.168.1.88"
    query_index = "wazuh-monitoring-3.x-2019.12.28"
    query_gte = "now-24h"
    query_lte = "now"
    size = 34900
    aggname = "basic_agg"

    #result = threat.basic_search(query_index, query_field, query_value, size, "match")

    # Pull aggregation of observed IP Addresses from recorded traffic
    recorded_traffic = inspected_data.basic_agg_search(query_index, query_field, size, query_gte, query_lte, aggname)

    # Debug - dump instance attributes

    for i in inspected_data.agg_results:
        observed_traffic.traffic_list.append(TrafficIP(i.result['key']))

    print(observed_traffic.traffic_list[0])




if __name__ == '__main__':
    main()