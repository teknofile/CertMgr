#!/usr/bin/env python

import os
import sys
import hvac
import base64
import getopt
import ConfigParser


CERTMGR_VERSION="0.1b"
glbVerbose = False

#####
#
# Notes: the token will be stored in memory, unencrypted
#
#####

# Specify the directory to write the certificate files
DIR_OUTPUT_DIR="/tmp"
CONFIG_FILE_PATH="./config.ini"

def main(argv):

# TODO: Allow config.ini to be overridden by command line opts
    try:
        opts, args = getopt.getopt(argv, "Vhsg", ["version", "help", "store", "get"])
    except getopt.GetoptError as err:
        print str(err)  # will print something like "option -a not recognized"
        printHelp() # TODO: print a usage output
        sys.exit(2)
        
    
    # TODO: Let's make sure we don't add -s and -g at the same time
    # This is a very hacky way...
    bStoreCerts = False
    bGetCerts = False
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp()
            sys.exit(3)
        elif opt in ("-V", "--version"):
            print("Version: " + CERTMGR_VERSION)
            sys.exit(3)
        elif opt in ("-s", "--store"):
            bStoreCerts = True
        elif opt in ("-g", "--get"):
            bGetCerts = True
            
    # This is a total hack, learn 2 use getopts better
    if bStoreCerts and bGetCerts:
        dbgMessage("Can't store and get at the same time.")
        print("Can't store and get at the same time!!")
        sys.exit(3)


    # Check to make sure that we have a config file
    if(os.path.isfile(CONFIG_FILE_PATH) == False):
        dbgMessage('Configuration file not found!')
        print("Fata Error. config.ini not found.")
        sys.exit(1)
        
    cfgMgrSettings = ConfigParser.ConfigParser()
    cfgMgrSettings.read("./config.ini")
    
    # Let's make sure there is a "CertMgr" section
    if (cfgMgrSettings.has_section("CertMgr") == False):
        dbgMessage("There isn't a CertMgr section in the config.ini file")
        print("Fatal Error. There needs to be a 'CertMgr' section in the configuration file.")
        sys.exit(1)
    else:
        glbVerbose = cfgMgrSettings.getboolean("CertMgr", "verbose_mode")

    for myCert in cfgMgrSettings.sections():
        if myCert != "CertMgr":
            certParams = dict([
                ('certDomain', myCert),
                ('vaultServer', cfgMgrSettings.get(myCert, "vault_server")),
                ('vaultTokenFile', cfgMgrSettings.get(myCert, "vault_token_file")),
                ('vaultKeyName', cfgMgrSettings.get(myCert, "vault_key_name")),
                ('savePath', cfgMgrSettings.get(myCert, "save_path")),
                ('saveCert', cfgMgrSettings.getboolean(myCert, "get_cert")),
                ('saveChain', cfgMgrSettings.getboolean(myCert, "get_chain")),
                ('saveFullChain', cfgMgrSettings.getboolean(myCert, "get_fullchain")),
                ('savePrivKey', cfgMgrSettings.getboolean(myCert, "get_privkey"))
            ])
                        
            if bGetCerts:
                getCert(certParams)
            elif bStoreCerts:
                storeCert(certParams)

def storeCert(certParams):
    sVaultToken = getVaultToken(certParams['vaultTokenFile'])

    try:
        # TODO: validate this URL is well formed. e.g. stupid quotes, is a real host, is https that kind of stuff
        vaultClient = hvac.Client(url=certParams['vaultServer'], token=sVaultToken)
    except KeyError:
        print("Error: Making connection to vault host: {}".format(certParams['vaultServer']))

    try:
        fHandle = open("/etc/letsencrypt/live/" + certParams['certDomain'] + "/cert.pem", "r")
        sCert = fHandle.read()
        fHandle.close()

        fHandle = open("/etc/letsencrypt/live/" + certParams['certDomain'] + "/chain.pem", "r")
        sChain = fHandle.read()
        fHandle.close()

        fHandle = open("/etc/letsencrypt/live/" + certParams['certDomain'] + "/fullchain.pem", "r")
        sFullChain = fHandle.read()
        fHandle.close()

        fHandle = open("/etc/letsencrypt/live/" + certParams['certDomain'] + "/privkey.pem", "r")
        sPrivKey = fHandle.read()
        fHandle.close()

        
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except:
        print "Unexpected error: " + sys.exc_info()[0]
        
    vaultClient.write(certParams['vaultKeyName'] + "/" + certParams['certDomain'],
                                  cert=base64.b64encode(sCert),
                                  chain=base64.b64encode(sChain),
                                  fullchain=base64.b64encode(sFullChain),
                                  privkey=base64.b64encode(sPrivKey))
    
    return True

def getCert(certParams):
    sVaultToken = getVaultToken(certParams['vaultTokenFile'])
    if certParams['saveCert'] == True:
        writeCertFile(certParams, "cert", sVaultToken)
    if certParams['saveChain'] == True:
        writeCertFile(certParams, "chain", sVaultToken)
    if certParams['saveFullChain'] == True:
        writeCertFile(certParams, "fullchain", sVaultToken)
    if certParams['savePrivKey'] == True:
        writeCertFile(certParams, "privkey", sVaultToken)

    return True
    
def writeCertFile(certParams, certFileExt, sVaultToken):
    try:
        fHandle = open(certParams['savePath'] + "/" + certParams['certDomain'] + "." + certFileExt, "w")
        fHandle.write(getVaultItem(certParams, certFileExt, sVaultToken))
        fHandle.close()
    except IOError as e:
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except:
        print "Unexpected error: " + sys.exc_info()[0]
        
    return True

def dbgMessage(sMessage):
    if glbVerbose == True:
        print("--- " + str(sMessage))
    
def printHelp():
    print("TODO: Do moar help plz.")
    sys.exit(3)
    
def getVaultToken(sTokenPath):
    sVaultToken = ""
    try:
        fileToken = open(sTokenPath)
        sVaultToken = fileToken.read()
        fileToken.close()
    except IOError as e:
        print("IO Error({0}): {1}".format(e.errno, e.message))
    except: 
        print("Unexpected error:" + sys.exec_info()[0])

    return sVaultToken.strip()

def getVaultItem(certParams, theKey, sVaultToken):
    # Valid options for "theKey" are:
    #   cert
    #   fullchain
    #   chain
    #   privkey
    # TODO: If it's not one of those, we should raise an exception

    try:
        # TODO: validate this URL is well formed. e.g. stupid quotes, is a real host, is https that kind of stuff
        vaultClient = hvac.Client(url=certParams['vaultServer'], token=sVaultToken)
    except KeyError:
        print("Error: Making connection to vault host: {}".format(certParams['vaultServer']))

    theResult = vaultClient.read(certParams['vaultKeyName'] + "/" + certParams['certDomain'])
    if theResult is None:
        dbgMessage("Unable to find secret: " + certParams['vaultKeyName'] + "/" + certParams['certDomain'])
        return ""
    else:
        try:
            return base64.decodestring(theResult['data'][theKey])
        except KeyError:
            dbgMessage(theResult)
            dbgMessage('Unable to find key in response data from Vault')
            return ""

    
if __name__ == "__main__":
    main(sys.argv[1:])
