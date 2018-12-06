# CertMgr 

## About

CertMgr is a Python script I wrote to help faciliate distributing SSL 
certificates in on my local network via an instance of <a href="https://vaultproject.io">Vault</a>. 

For services that I want encrypted, I use LetsEncrypt certificates
and a single host on my local network has the appropriate access
to validate the host/domain and renew the certificate(s). Including
wildcard certs. 

My issues arose when it came time to distribute those certificates to 
the right applications (which could be/are) running all over the place.

This script has the ability to store the new certificate, chain, priv key
in the vault. It also has the ability to pull the certificate(s) from the 
vault and write them to disk.

I didn't feel very comfortable distributing keys via puppet and the like, 
so I wrote this.

## Usage / Install

### Install
There are a few python modules you will need to make sure are installed. They
should be defined within the requirements.txt file. Install them via pip:

`pip install -r src/requirements.txt`

### Usage

Setup the config.ini file first. You need to add sections via [blah] to drive which 
certificates the CertMgr.py script is dealing with. You need to also keep the [CertMgr] 
section or it won't run. 

When config.ini is setup:

Iterate through the defined certificates and get them from vault and save them appropriately:
`./CertMgr.py -g`

Iterate through the defined certificates and store them in the vault:
`./CertMgr.py -s`

you can also (eventually) run `./CertMgr.py -h` for more in-depth help. 

### Misc Issues

I did run into some issues installing on a raspberry pi. Pip versions way too old. I ended
up doing a `pip install --upgrade pip` then installing the requirements using the copy of pip
at /usr/local/bin/pip.... YMMV.