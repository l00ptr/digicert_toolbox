#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OpenSSL import crypto, SSL
import sys
import requests
import json
import transaction
from certlib import config_certificate, digicert_api_key,\
        digicert_api_url, headers
from certlib.digicert import get_orders_data, get_order_data, submit_csr,\
        download_cert, list_pending
from certlib.persistent import configure_storage
import traceback


class CertificateController:
    def __init__(self):
        self.country_code = config_certificate.get('certificates',
                                                   'contry_code')
        self.locality = config_certificate.get('certificates', 'locality')
        self.state = config_certificate.get('certificates', 'state')
        self.orga = config_certificate.get('certificates', 'orga')
        self.datastore = config_certificate.get('certificates', 'datastore')
        self.cert_storage = configure_storage()

    def generate_and_submit_csr(self, nodename, sans=[]):
        cert = Certificate(nodename, self.country_code,
                           self.locality, self.state, self.orga, sans)
        try:
            csr = cert.generate_CSR(self.datastore)
            csr_submission_result = submit_csr(csr, nodename, sans)
        except:
            print("error thrown")
            traceback.print_exc()
        else:
            self.cert_storage[nodename] = {'csr_result': csr_submission_result,
                                           'certificate': cert}

            transaction.commit()

    def list_certificates(self):
        for nodename, a_cert in self.cert_storage.items():
            try:
                for key, value in a_cert['csr_result'].items():
                    self.print_cert(value)
            except:
                pass

    def download_cert(self, nodename):
        valid_certs_id = [cert_id for cert_id, cert_info in
                          self.cert_storage[nodename]['csr_result'].items()
                          if cert_info['status'] == 'issued'
                          ]
        cert_id_downloadable = max(valid_certs_id)
        self.print_cert(self.cert_storage[nodename]['csr_result']
                        [cert_id_downloadable])
        # Remove downalodable cert in case we want to give non downalodable
        # certs info as a user feedback
        valid_certs_id.remove(cert_id_downloadable)
        download_cert(self.cert_storage[nodename]['csr_result']
                      [cert_id_downloadable]
                      ['certificate']['id'], nodename)

    def print_cert(self, certificate):
        print("*"*80)
        print("{0:<20}{1: <26}".format("Order ID:", certificate['id']))
        # print("{0:<20}{1: <26}")
        print("{0:<20}{1: <26}".format("Type:",
                                       certificate['product']['name']))
        print("{0:<20}{1: <26}".format("Status:", certificate['status']))
        try:
            print("{0:<20}{1: <26}".format("Certificate ID:",
                                           certificate['certificate']['id']))
            print("{0:<20}{1: <26}".format("Valid untill:", (certificate
                                                             ['certificate']
                                                             ['valid_till'])))
            print("="*80)
            print("List of associated dns names:")
            print("="*80)
            list(map(lambda a_dns_name: print(a_dns_name),
                 certificate['certificate']['dns_names']))
        except:
            pass

    def update_certificates_data(self):
        orders_data = get_orders_data()
        for an_order_data in orders_data['orders']:
            nodename = an_order_data['certificate']['common_name']
            try:
                certificate_data = self.cert_storage[nodename]['certificate']
            except:
                certificate_data = None
            try:
                csr_result = self.cert_storage[nodename]['csr_result']
            except:
                csr_result = {}
            csr_result[int(an_order_data['id'])] = an_order_data
            self.cert_storage[nodename] = {'csr_result': csr_result,
                                           'certificate': certificate_data}
        transaction.commit()


class Certificate:

    def __init__(self, nodename, country_code, locality, state, orga, sans=[]):
        self.nodename = nodename
        self.sans = sans
        self.country_code = country_code
        self.locality = locality
        self.state = state
        self.orga = orga
        self.submission_result = None
        self.csr_content = None

    # Generate Certificate Signing Request (CSR)
    def generate_CSR(self, datastore):
        csrfile = "{}/{}.csr".format(datastore, self.nodename)
        keyfile = "{}/{}.key".format(datastore, self.nodename)
        TYPE_RSA = crypto.TYPE_RSA
        # Appends SAN to have 'DNS:'
        ss = []
        for i in self.sans:
            ss.append("DNS: %s" % i)
        ss = ", ".join(ss).encode('ascii')

        req = crypto.X509Req()
        req.get_subject().CN = self.nodename
        req.get_subject().countryName = self.country_code
        req.get_subject().stateOrProvinceName = self.state
        req.get_subject().localityName = self.locality
        req.get_subject().organizationName = self.orga

        base_constraints = ([
            crypto.X509Extension(b"keyUsage", False,
                                 b"Digital Signature, Non Repudiation, \
                                 Key Encipherment"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        ])
        x509_extensions = base_constraints
        # If there are SAN entries, append the base_constraints to include them
        if ss:
            san_constraint = crypto.X509Extension(str.encode("subjectAltName"),
                                                  False, ss)
            x509_extensions.append(san_constraint)
        req.add_extensions(x509_extensions)
        # Utilizes generateKey function to kick off key generation.
        key = self.generate_pkey(TYPE_RSA, 2048)
        req.set_pubkey(key)

        req.sign(key, "sha256")
        self.csr_content = crypto.dump_certificate_request(crypto.FILETYPE_PEM,
                                                           req)
        self.write_files(csrfile, req)
        self.write_files(keyfile, key)
        return self.csr_content

    def get_csr(self):
        return self.csr_content

    # Generate Private Key
    def generate_pkey(self, type, bits):
        key = crypto.PKey()
        key.generate_key(type, bits)
        return key

    # Generate .csr/key files.
    def write_files(self, mkFile, request):
        if mkFile.endswith(".csr"):
            with open(mkFile, "wb") as f:
                f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM,
                                                        request))
        elif mkFile.endswith(".key"):
            with open(mkFile, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        else:
            print("Failed.")
            exit()
