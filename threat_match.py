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
        self.name = name
        self.e_cli_ip = e_cli_ip
        self.e_cli_port = e_cli_port
        self.e_cli_proto = e_cli_proto
        self.e_cli_target = self.e_cli_proto + self.e_cli_ip + ":" + self.e_cli_port
        self.initial_status = 200

        self.check_client_requests()

        if self.checked == 0:
            print("Connected not checked, now checking")

        if self.initial_status == 200:
            print("Initial cluster check appears OK.......")
            print("Now checking health")
        else:
            print("There seems to be a problem")


    def __str__(self):
        return str(self.__class__) + '\n' + '\n'.join(('{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__)



def main():
    threatmatch = Threat_match("poc", e_client_ip, e_client_port, e_client_proto)
    return

if __name__ == '__main__':
    main()