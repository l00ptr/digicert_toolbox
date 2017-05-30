Digicert ToolBox
================

Digicert toolbox provides a few scripts to manage the certificates lifecycle

Done and Ok:
 - Certificate download script (once the certificate validated we can download
   it with the download_cert.py script)
 - generate private key
 - generate CSR (with and without SANS)
 - submit CSR to digicert

ToDo:
 - Add a few tests
 - Certificate validation directly from this tool (a co-worker still need to
   do it through the digicert website)

Usage
=====

First you need to copy and edit the sample config file from:
 - config/config_certificate.ini.sample

to
 - config/config_certificate.ini

And then edit this file to match your settings


Generate and submit csr
-----------------------

Beware there is no testing flag at this moment so calling this script will
generate a CSR and submit it to digicert if you are allowed

```
python3 generate_cert.py fqdn.example.org --san prettyname.example.org
```

This script will create a private key, submit the CSR to digicert and add a 
record about it into our datastore (zodb datastore containing some data about
the CSR/certificate we manage through this toolbox, you can compare that to 
the database managed by apt or yum but for your certs)

Download a certificate
----------------------

There is a script to directly download a certificate from the CLI
```
python3 download_cert.py fqdn.example.org
```

Download operation is limited to certificates managed and known by this toolbox,
So if you didn't submit the CSR with the generate_cert.py you will have to run 
the update_data.py to populate the datastore and download the certificate 
through the download script.


Special Thanks
==============

Thx to @cjcotton and @erantanen for the inspring code
