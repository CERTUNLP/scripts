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
from http.client import HTTPSConnection
import re, datetime, requests
from send_mail import MailLog
import sys, traceback
import config_spamhaus

send_external = False

url_internal_staging = config_spamhaus.NGEN["url_internal_staging"]
url_external_staging = config_spamhaus.NGEN["url_external_staging"]
url_prod = config_spamhaus.NGEN["url_prod"]

cert = config_spamhaus.SPAMHAUS["cert"]
key = config_spamhaus.SPAMHAUS["key"]

maillog = MailLog(config_spamhaus.MAILLOG)

def process_file():
    ## This sets up the https connection
    c = HTTPSConnection("cert-data.spamhaus.org")

    ## then connect
    c.request('GET', '/api/bots?cert={0}&key={1}'.format(cert,key), headers={})

    ## get the response back
    res = c.getresponse()

    ## at this point you could check the status etc
    ## this gets the page text
    data = res.read().decode('utf-8', errors='ignore').split('\n')
    #print(data)

    if data[18] != '; ip, asn, country, lastseen, botname, domain, remote_ip, remote_port, local_port, protocol':
        raise Exception('El formato de la pagina es distinto al original')

    reports = data[20:-2]
    report_header = data[:20]
    #print( reports)
    return report_header,[item.split(',') for item in reports]

def isUNLP(ip):
    return ip[:7] == '163.10.'

def process_lines(header, lines):
    headers = {'Accept' : '*/*', 'Expect': '100-continue'}
    externals = []
    log_info = []
    error = False
    for line in lines:
        evidence = ','.join(line)
        report = dict(
                    type = "malware",
                    hostAddress = line[0],
                    feed = "spamhaus"
                )
        files = {'evidence_file': ("evidence.txt", header[18]+"\n"+evidence, 'text/plain', {'Expires': '0'})}
        if isUNLP(line[0]):
            #log_info.append(str(evidence))
            response = requests.post(url_prod, data=report, headers=headers, files=files, verify=False)
            if response.status_code != 201:
                error = True
                log_info.append(str(response)+str(response.text)+str(report))
                log_info.append(str(files))
        elif send_external:
            response = requests.post(url_external_staging, data=report, headers=headers, files=files, verify=False)
            if response.status_code != 201:
                error = True
                log_info.append('\n'+str(response)+'\n'+str(response.text)+'\n'+str(report)+'\n')
                log_info.append(str(files)+'\n\n')

    # Send info_log via mail
    log_report = '\n'.join(log_info)
    if error:
        maillog.sendError(log_report)
    else:
        maillog.sendInfo("Completed successful")


try:
    header, lines = process_file()
    process_lines(header, lines)
except Exception as e:
    et, ev, etb = sys.exc_info()
    time = str(datetime.datetime.now())
    tbinfo = traceback.format_tb(etb)#[0]
    debugmsg = "\nTraceback info:\n" + ''.join(tbinfo) + "\n"
    fullmsg = "exception in SpamHaus: \n" + time + debugmsg+str(et.__name__)+":"+str(ev)+"\n"
    maillog.sendError(fullmsg)
    print (e)
