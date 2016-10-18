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
################################################################
## This script notifies you when new data exists on botnetcc ###
################################################################

from http.client import HTTPSConnection
import re, datetime, requests
from send_mail import MailLog
import sys, traceback
import config_spamhaus_botnet

cert = config_spamhaus_botnet.SPAMHAUS["cert"]
key = config_spamhaus_botnet.SPAMHAUS["key"]

maillog = MailLog(config_spamhaus_botnet.MAILLOG)

def process_file():
    ## This sets up the https connection
    c = HTTPSConnection("cert-data.spamhaus.org")

    ## then connect
    c.request('GET', '/api/botnetcc?cert={0}&key={1}'.format(cert,key), headers={})

    ## get the response back
    res = c.getresponse()

    ## at this point you could check the status etc
    ## this gets the page text
    data = res.read().decode('utf-8', errors='ignore')
    #print(data)
    lines = data.split('\n')

    if len(lines) > 5 or lines[3] != ";":
        maillog.sendReport(file_name="reporte_botnet.txt", file_content=data)

try:
    process_file()
except Exception as e:
    et, ev, etb = sys.exc_info()
    time = str(datetime.datetime.now())
    tbinfo = traceback.format_tb(etb)#[0]
    debugmsg = "\nTraceback info:\n" + ''.join(tbinfo) + "\n"
    fullmsg = "exception in SpamHaus: \n" + time + debugmsg+str(et.__name__)+":"+str(ev)+"\n"
    maillog.sendInfo(fullmsg)
    print (e)
