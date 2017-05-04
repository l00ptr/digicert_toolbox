#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
from certlib import digicert
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Provide the FQDN", action="store")
    parser.add_argument("-s", "--san", help="SANS", action="store",
                        nargs='*', default="")

    args = parser.parse_args()

    hostname = args.name
    sans = args.san
    digicert.generate_CSR(hostname, sans)
