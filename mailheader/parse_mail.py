#!/usr/bin/python3
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#
# Author: Mateo Durante <mdurante@cert.unlp.edu.ar>
# Adapted by: Nicolas Macia <nmacia@cert.unlp.edu.ar>
#
import sys
from email.parser import HeaderParser
import re, ipaddress
from pprint import pprint

# Create your models here.
class MailHeader():
    parser = HeaderParser()
    re_ipv4 = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
    #re_ipv6 = re.compile('^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$')

    def is_global(self, ip):
        return not (ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_private or ip.is_reserved or ip.is_unspecified)

    def getHeaders(self, mail):
        return self.parser.parsestr(mail)

    def getAllWithKey(self, headers, key):
        return headers.get_all(key)

    def getAllReceived(self, mail):
        return self.getAllWithKey(self.getHeaders(mail), 'Received')

    def asIP(self, text):
        try:
            return ipaddress.ip_address(text)
        except ValueError:
            pass

    def searchIP(self, text):
        regex = self.re_ipv4.findall(text)
        #regex += self.re_ipv6.findall(text)
        return list(filter(None, [self.asIP(e) for e in regex]))

    def searchIPOrigin(self, mail):
        headers = self.getAllReceived(mail)
        if headers:
            for ips in reversed(headers):
                for ip in self.searchIP(ips):
                    if self.is_global(ip):
                        return ip

    def allAbout(self, mail):
        origin = self.searchIPOrigin(mail)
        has_reply = [self.getHeaders(mail).get('From')]
        has_reply += [self.getHeaders(mail).get('Reply-To')]
        headers = []
        for k, v in self.getHeaders(mail).items():
            data = {}
            data['type'] = k
            data['value'] = v
            if k == "Received":
                ip = self.searchIP(v)
                data['parsed'] = {'ip': [ x.exploded for x in ip ]}
                data['parsed']['has_global'] = [ self.is_global(x) for x in ip ]
                if origin in ip:
                    data['parsed']['is_origin'] = origin.exploded
            else:
                # searching IPs for fun
                ip = self.searchIP(v)
                data['parsed'] = {'ip': [ x.exploded for x in ip ]}
                data['parsed']['has_global'] = [ self.is_global(x) for x in ip ]
                # searching who to reply
                if k in ['From', 'Reply-To']:
                    # From and Reply-To has priority
                    data['parsed']['to_reply'] = True
                elif not has_reply and k in ['Return-Path', 'Sender']:
                    # Return-Path and Sender are SMTP headers that may be present
                    data['parsed']['to_reply'] = True
            headers.append(data)
        return headers


if __name__ == "__main__":

    if (len(sys.argv) < 2):
        print ('Use: python3 <file> [--all]')
        exit()

    data = open(sys.argv[1], 'r').read()

    mh = MailHeader()
    all_parsed = mh.allAbout(data)
    ip_origin = mh.searchIPOrigin(data)

    print ("\n IP ORIGIN")
    print ("--------------")
    print (ip_origin)

    #pprint (all_parsed)
    if len(sys.argv) == 3 and sys.argv[2] == "--all": 
        print ("\n ALL HEADERS")
        print ("--------------")
        for h in all_parsed:
            print("Header: {0}\nValue: {1}\n".format(h['type'], h['value']))