#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
config_certificate = configparser.ConfigParser()
config_certificate.read('../config/config_certificate.ini')
digicert_api_url = config_certificate.get('digicert', 'api_url')

digicert_api_key = config_certificate.get('digicert', 'api_key')
headers = {
    'X-DC-DEVKEY': digicert_api_key,
    'User-agent': 'Mozilla/5.0',
    'Accept': '*/*'
}
