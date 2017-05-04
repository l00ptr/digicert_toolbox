#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL import crypto, SSL
import sys
import requests
import json
from requests.auth import HTTPBasicAuth
from certlib import config_certificate, digicert_api_key,\
        digicert_api_url, headers


def submit_csr_digicert(csr_obj, nodename, sans=[]):
    order_ev_multi_endpoint = config_certificate.get('digicert',
                                                     'order_ev_multi_endpoint')
    orga_unit = config_certificate.get('certificates', 'orga_unit')
    orga_id = config_certificate.get('certificates', 'orga_id')
    headers['Content-Type'] = "application/json"
    data = {
        "certificate": {
            "common_name": nodename,
            "dns_names": sans,
            "csr": str(csr_obj).replace("\\n", ""),
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


def download_cert(cert_id):

    download_endpoint = config_certificate.get('digicert',
                                               'download_endpoint')
    download_endpoint = download_endpoint.format(certificate_id=cert_id)
    download_endpoint = "{}/{}".format(digicert_api_url, download_endpoint)
    # @todo: define how to save the response!
    response = requests.get(download_endpoint, headers=headers)
    response.raise_for_status()
    with open('/tmp/test.zip', 'wb') as f:
        f.write(response.content)


def list_pending():
    order_endpoint = "{}/{}".format(digicert_api_url, "report/request")
    response = requests.get(order_endpoint, headers=headers)
    response.raise_for_status()
    print(response.text)


# Generate Certificate Signing Request (CSR)
def generate_CSR(nodename, sans=[]):
    try:

        country_code = config_certificate.get('certificates', 'contry_code')
        locality = config_certificate.get('certificates', 'locality')
        state = config_certificate.get('certificates', 'state')
        orga = config_certificate.get('certificates', 'orga')
        datastore = config_certificate.get('certificates', 'datastore')
        # server_url=config_referentiel.get('referentiel','url')
    except Exception as e:
        print("Impossible to configure, config file or value missing")
        sys.exit(2)
    csrfile = "{}/{}.csr".format(datastore, nodename)
    keyfile = "{}/{}.key".format(datastore, nodename)
    print(keyfile)
    TYPE_RSA = crypto.TYPE_RSA
    # Appends SAN to have 'DNS:'
    ss = []
    for i in sans:
        ss.append("DNS: %s" % i)
    ss = ", ".join(ss).encode('ascii')

    req = crypto.X509Req()
    req.get_subject().CN = nodename
    req.get_subject().countryName = country_code
    req.get_subject().stateOrProvinceName = state
    req.get_subject().localityName = locality
    req.get_subject().organizationName = orga
    # req.get_subject().organizationalUnitName = OU

    # Add in extensions
    # added bytearray to string
    # before -> "keyUsage"
    # after  -> b"keyUsage"

    base_constraints = ([
        crypto.X509Extension(b"keyUsage", False,
                             b"Digital Signature, Non Repudiation, \
                             Key Encipherment"),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])
    x509_extensions = base_constraints
    # If there are SAN entries, append the base_constraints to include them.
    if ss:
        san_constraint = crypto.X509Extension(str.encode("subjectAltName"),
                                              False, ss)
        x509_extensions.append(san_constraint)
    req.add_extensions(x509_extensions)
    # Utilizes generateKey function to kick off key generation.
    key = generate_pkey(TYPE_RSA, 2048)
    req.set_pubkey(key)

    # change to sha 256?
    # req.sign(key, "sha1")
    req.sign(key, "sha256")
    csr_content = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    submit_csr_digicert(csr_content, nodename, sans)
    write_files(csrfile, req)
    write_files(keyfile, key)

    return req


# Generate Private Key
def generate_pkey(type, bits):
    key = crypto.PKey()
    key.generate_key(type, bits)
    return key


# Generate .csr/key files.
def write_files(mkFile, request):
    if mkFile.endswith(".csr"):
        f = open(mkFile, "wb")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
        f.close()

    elif mkFile.endswith(".key"):
        f = open(mkFile, "wb")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        f.close()
    else:
        print("Failed.")
        exit()
