#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
from certlib.cert import CertificateController
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Provide the FQDN", action="store")

    args = parser.parse_args()

    nodename = args.name
    cert_controller = CertificateController()
    cert_controller.download_cert(nodename)
