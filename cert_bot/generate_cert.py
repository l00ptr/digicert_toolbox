#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
from certlib.cert import CertificateController
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Provide the FQDN", action="store")
    parser.add_argument("-s", "--san", help="SANS", action="store",
                        nargs='*', default="")

    args = parser.parse_args()

    nodename = args.name
    sans = args.san
    cert_controller = CertificateController()
    cert_controller.generate_and_submit_csr(nodename, sans)
