#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL import crypto, SSL
import sys
import requests
import json
from certlib import config_certificate, digicert_api_key,\
        digicert_api_url, headers


def submit_csr_digicert(csr, nodename, sans=[]):
    order_ev_multi_endpoint = config_certificate.get('digicert',
                                                     'order_ev_multi_endpoint')
    orga_unit = config_certificate.get('certificates', 'orga_unit')
    orga_id = config_certificate.get('certificates', 'orga_id')
    headers['Content-Type'] = "application/json"
    data = {
        "certificate": {
            "common_name": nodename,
            "dns_names": sans,
            "csr": str(csr).replace("\\n", ""),
            "server_platform": 2,
            "organization_units": [orga_unit],
            "signature_hash": "sha256"
        },
        "validity_years": 2,
        "organization": {
            "id": orga_id
        },

    }
    order_endpoint = "{}/{}".format(digicert_api_url, order_ev_multi_endpoint)
    response = requests.post(order_endpoint, data=json.dumps(data),
                             headers=headers)
    response.raise_for_status()
    return json.loads(response.text)


def download_cert(cert_id):

    datastore = config_certificate.get('certificates', 'datastore')
    download_endpoint = config_certificate.get('digicert',
                                               'download_endpoint')
    download_endpoint = download_endpoint.format(certificate_id=cert_id)
    download_endpoint = "{}/{}".format(digicert_api_url, download_endpoint)
    # @todo: define how to save the response!
    response = requests.get(download_endpoint, headers=headers)
    response.raise_for_status()
    archive_dest = "{datastore}/{cert_id}.zip".format(datastore=datastore,
                                                      cert_id=cert_id)
    with open(archive_dest, 'wb') as f:
        f.write(response.content)


def list_pending():
    order_endpoint = "{}/{}".format(digicert_api_url, "report/request")
    response = requests.get(order_endpoint, headers=headers)
    response.raise_for_status()
    print(response.text)
