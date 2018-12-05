== CertMgr ==

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

= Usage =

TBD
