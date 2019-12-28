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
    print(threat)
    print("\n\n\n\n\n\n")
    print("lets do that again")
    threat.update_cluster_status()


if __name__ == '__main__':
    main()