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
# Another option for this library is using rdap_wrapper.py
#
import json
import requests
import pprint

class RDAP:
    arin_rdap_url = 'https://rdap.arin.net/registry/ip/{0}'

    def get_value(self, entry):
        if entry[0] == 'adr':
            if list == type(entry[-1]):
                value = ', '.join(filter(None,entry[-1]))
            else:
                value = entry[-1]
        else:
            value = entry[-1]
        return value

    def add_role_values(self, entity, abuse_data, role):
        if role in entity['roles']:
            abuse_data[role] = {}
            try:
                for entry in entity['vcardArray'][1]:
                    abuse_data[role][entry[0]] = self.get_value(entry)
            except KeyError:
                abuse_data[role] = None


    def get_ip_abuse_emails(self, host_ip,
                            roles=['abuse','noc','technical','registrant']):
        # ARIN redirect you to the correct rdap service.
        session = requests.Session()
        response = session.get(self.arin_rdap_url.format(host_ip))

        if response.status_code != 200:
            return ['Error connecting arin rdap.']

        abuse_data = dict()
        entities = json.loads(response.text)['entities']
        while entities:
            entity = entities.pop(0)
            entities += entity['entities'] if 'entities' in entity else []
            if 'roles' in entity:
                for rol in roles:
                    self.add_role_values(entity, abuse_data, rol)
        return abuse_data
