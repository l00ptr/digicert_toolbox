#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
from certlib import digicert
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert_id", help="Provide the id of the \
        certificate you want to download", action="store")
    args = parser.parse_args()

    cert_id = args.cert_id
    digicert.list_pending()
    digicert.download_cert(cert_id)
