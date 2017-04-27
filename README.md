Digicert ToolBox
----------------

Digicert toolbox to automaticly generate and submit CSR

Done and Ok:
 - generate private key 
 - generate CSR (with and without SANS)
 - submit CSR to digicert

ToDo:
 - Add a few tests
 - Certificate validation directly from this tool (a co-worker still need to 
   do it through the digicert website)
 - Certificate download script (still need to use the digicert website)

Usage
-----

First you need to copy and edit the sample config file from:
 - config/config_certificate.ini.sample

to 
 - config/config_certificate.ini

And then edit this file to match your settings 


Generate and submit csr
~~~~~~~~~~~~~~~~~~~~~~~

Beware there is no testing flag at this moment so calling this script will
generate a CSR and submit it to digicert if you are allowed 

```
python3 generate_cert.py fqdn.example.org --san prettyname.example.org
```

Special Thanks
--------------

Thx to @cjcotton and @erantanen for the inspring code 
