#!/bin/python3
#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#
# Author: Mateo Durante <mdurante@cert.unlp.edu.ar>
#
# Another option for this wrapper is using RDAP from rdap_query
#
import json
import requests
from ipwhois import IPWhois
import pprint

class WhoisLib:
    ipwhois = ''

    def __init__(self, ip):
        self.ipwhois = IPWhois(ip)

    def setIP(self, ip):
        self.ipwhois = IPWhois(ip)

    def getWhois(self):
        return self.ipwhois.lookup_whois(inc_raw=True)

    def getRDAP(self):
        return self.ipwhois.lookup_rdap()
