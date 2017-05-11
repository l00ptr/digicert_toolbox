#!/usr/bin/env python
# -*- coding: utf-8 -*-
from certlib import config_certificate
from ZODB import FileStorage, DB
from certlib import config_certificate


def configure_storage():

    datastore = config_certificate.get('certificates', 'datastore')
    metadata_db_name = config_certificate.get('certificates',
                                              'metadata_db_name')
    storage_path = "{datastore}/{metadata_db_name}".format(datastore=datastore,
                                                           metadata_db_name=
                                                           metadata_db_name)
    storage = FileStorage.FileStorage(storage_path)
    db = DB(storage)
    connection = db.open()
    root = connection.root()
    return root
