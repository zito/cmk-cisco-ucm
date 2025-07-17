#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.
"""Check_MK Cisco Unified Communications Manager Control Center Services Special Agent"""

# Based heavily on agent_vsphere.py :-)
# https://developer.cisco.com/docs/sxml/#!control-center-services-api-reference

import argparse
import re
import socket
import sys

import requests
from requests.auth import HTTPBasicAuth

import urllib3  # type: ignore[import]

import cmk.utils.password_store
import cmk.utils.paths



#   .--defines-------------------------------------------------------------.
#   |                      _       __ _                                    |
#   |                   __| | ___ / _(_)_ __   ___  ___                    |
#   |                  / _` |/ _ \ |_| | '_ \ / _ \/ __|                   |
#   |                 | (_| |  __/  _| | | | |  __/\__ \                   |
#   |                  \__,_|\___|_| |_|_| |_|\___||___/                   |
#   |                                                                      |
#   '----------------------------------------------------------------------'


class SoapTemplates:
    # yapf: disable
    GETSERVICESTATUS = (
        '<ns1:soapGetServiceStatus>'
        '  <ns1:ServiceStatus></ns1:ServiceStatus>'
        '</ns1:soapGetServiceStatus>'
    )
    # yapf: enable

    def __init__(self):
        super(SoapTemplates, self).__init__()
        self.getservicestatus = SoapTemplates.GETSERVICESTATUS


# .
#   .--args----------------------------------------------------------------.
#   |                                                                      |
#   |                          __ _ _ __ __ _ ___                          |
#   |                         / _` | '__/ _` / __|                         |
#   |                        | (_| | | | (_| \__ \                         |
#   |                         \__,_|_|  \__, |___/                         |
#   |                                   |___/                              |
#   '----------------------------------------------------------------------'


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)

    # flags
    parser.add_argument(
        "--debug", action="store_true", help="""Debug mode: let Python exceptions come through""")
    parser.add_argument(
        "--no-cert-check", action="store_true",
        help="""Disables the checking of the servers ssl certificate""")

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=60,
        help="""Set the network timeout to CUCM to SECS seconds. The timeout is not only
        applied to the connection, but also to each individual subquery.""")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8443,
        help="""Alternative port number (default is 8443 for the https connection).""")

    # optional arguments (from a coding point of view - should some of them be mandatory?)
    parser.add_argument("-u", "--user", default=None, help="""Username for login""")
    parser.add_argument("-s", "--secret", default=None, help="""Password for login""")

    # positional arguments
    parser.add_argument("host_address",
                        metavar="HOST",
                        help="""Host name or IP address of Cisco UCM Control Center Services""")

    return parser.parse_args(argv)


#.
#   .--Connection----------------------------------------------------------.
#   |             ____                       _   _                         |
#   |            / ___|___  _ __  _ __   ___| |_(_) ___  _ __              |
#   |           | |   / _ \| '_ \| '_ \ / _ \ __| |/ _ \| '_ \             |
#   |           | |__| (_) | | | | | | |  __/ |_| | (_) | | | |            |
#   |            \____\___/|_| |_|_| |_|\___|\__|_|\___/|_| |_|            |
#   |                                                                      |
#   '----------------------------------------------------------------------'


class CUCMUnauthorized(RuntimeError):
    """ 401 Unauthorized """
    pass

class CUCMForbidden(RuntimeError):
    """ 403 Forbidden """
    pass

class CUCMUndecoded(RuntimeError):
    """ XXX Undecoded """
    pass


class CUCMSession(requests.Session):
    """Encapsulates the Sessions with the CUC system"""
    ENVELOPE = ('<SOAP-ENV:Envelope'
                ' xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
                ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
                ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                '<SOAP-ENV:Header></SOAP-ENV:Header>'
                '<SOAP-ENV:Body xmlns:ns1="http://schemas.cisco.com/ast/soap">%s</SOAP-ENV:Body>'
                '</SOAP-ENV:Envelope>')

    def __init__(self, address, port, no_cert_check=False, user=None, secret=None):
        super(CUCMSession, self).__init__()
        if no_cert_check:
            # Watch out: we must provide the verify keyword to every individual request call!
            # Else it will be overwritten by the REQUESTS_CA_BUNDLE env variable
            self.verify = False
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

        self._post_url = "https://%s:%s/controlcenterservice2/services/ControlCenterServices?wsdl" % (address, port)
        self.headers.update({
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": "urn:vim25/5.0",
            "User-Agent": "Checkmk special agent Cisco UCM",
        })
        if user is not None and secret is not None:
            self.auth = HTTPBasicAuth(user, secret)

    def postsoap(self, request):
        soapdata = CUCMSession.ENVELOPE % request
        # Watch out: we must provide the verify keyword to every individual request call!
        # Else it will be overwritten by the REQUESTS_CA_BUNDLE env variable
        return super(CUCMSession, self).post(self._post_url, data=soapdata, verify=self.verify)


class CUCMConnection:

    def __init__(self, address, port, opt):
        super(CUCMConnection, self).__init__()

        self._session = CUCMSession(address, port, opt.no_cert_check, opt.user, opt.secret)
        self._soap_templates = SoapTemplates()

    def query_server(self, method, **kwargs):
        payload = getattr(self._soap_templates, method) % kwargs
        response = self._session.postsoap(payload)
        if response.status_code == 200:
            return response.text
        if response.status_code == 401:
            raise CUCMUnauthorized("401 Unauthorized")
        if response.status_code == 403:
            raise CUCMForbidden("403 Forbidden")
        raise CUCMUndecoded(f"{response.status_code} Undecoded status code")


#.
#   .--unsorted------------------------------------------------------------.
#   |                                       _           _                  |
#   |            _   _ _ __  ___  ___  _ __| |_ ___  __| |                 |
#   |           | | | | '_ \/ __|/ _ \| '__| __/ _ \/ _` |                 |
#   |           | |_| | | | \__ \ (_) | |  | ||  __/ (_| |                 |
#   |            \__,_|_| |_|___/\___/|_|   \__\___|\__,_|                 |
#   |                                                                      |
#   '----------------------------------------------------------------------'


def get_pattern(pattern, line):
    return re.findall(pattern, line, re.DOTALL) if line else []

def fetch_servicestatus(con):
    response = con.query_server('getservicestatus')
    items = get_pattern(
        '<ns1:ServiceName>(.*?)</ns1:ServiceName>'
            '<ns1:ServiceStatus>(.*?)</ns1:ServiceStatus>'
            '<ns1:ReasonCode>(.*?)</ns1:ReasonCode>'
            '<ns1:ReasonCodeString>(.*?)</ns1:ReasonCodeString>',
        response)
    return items


def fetch_data(con, opt):
    output = []
    servicestatus = fetch_servicestatus(con)
    output.append("<<<cisco_ucm_services:sep(124)>>>")
    output += ["|".join(entry) for entry in servicestatus]
    return output


#.
#   .--Main----------------------------------------------------------------.
#   |                        __  __       _                                |
#   |                       |  \/  | __ _(_)_ __                           |
#   |                       | |\/| |/ _` | | '_ \                          |
#   |                       | |  | | (_| | | | | |                         |
#   |                       |_|  |_|\__,_|_|_| |_|                         |
#   |                                                                      |
#   '----------------------------------------------------------------------'


def main(argv=None):
    if argv is None:
        cmk.utils.password_store.replace_passwords()
        argv = sys.argv[1:]

    opt = parse_arguments(argv)

    socket.setdefaulttimeout(opt.timeout)
    try:
        con = CUCMConnection(opt.host_address, opt.port, opt)
        output = fetch_data(con, opt)

    except Exception as exc:
        if opt.debug:
            raise
        sys.stderr.write("%s\n" % exc)
        return 1

    sys.stdout.writelines("%s\n" % line for line in output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
