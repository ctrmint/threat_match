#! /usr/bin/env python3
#

from elasticsearch import *
from enviro import *
from Threatmatch import *


def main():
    ip_scratch_list = []
    observed_traffic = []
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
        if i.result['key'] not in ip_scratch_list:
             # New IP address to record in observed_traffic
            ip_scratch_list.append(i.result['key'])
            observed_traffic.append(TrafficIP(i.result['key']))
        else:
            # IP already present, need to increment counter, and set pending check value
            for n in observed_traffic:
                if n.ip_address == i.result['key']:
                    n.ip_address_instance_counter += 1


    for p in observed_traffic:
        print(p.ip_address, p.ip_address_instance_counter, p.pending_check, p.type)

if __name__ == '__main__':
    main()