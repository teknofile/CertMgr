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

def main(argv):  
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
            
            getCert(certParams)
            
        
    # TODO: Make these variables configurable
    VAULT_SERVER=""
    VAULT_TOKEN_PATH=""
    VAULT_KEYROOT=""

    sVaultToken = ""
    
    
    # Move these higher in the main function
    try:
        opts, args = getopt.getopt(argv, "Vh:", ["version"])
    except getopt.GetoptError:
        print(sys.argv[0] + " [options]")
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            printHelp()
        elif opt in ("-V", "--version"):
            print("Version: " + CERTMGR_VERSION)
            sys.exit(3)

    sVaultToken = getVaultToken(VAULT_TOKEN_PATH)

    # TODO: We shouldn't hardcode copperdale.teknofile.net
    certDomain = "copperdale.teknofile.net"
    for theCert in ("cert", "fullchain", "chain", "privkey"):
        fileCert = open(DIR_OUTPUT_DIR + "/" + certDomain + "." + theCert, "w")
        fileCert.write(getVaultItem(certDomain, theCert, VAULT_SERVER, sVaultToken, VAULT_KEYROOT))

def getCert(certParams):
    # TODO: Need exception handling around all of this file I/O
    sVaultToken = getVaultToken(certParams['vaultTokenFile'])
    if certParams['saveCert'] == True:
        try:
            fileCert = open(certParams['savePath'] + "/" + certParams['certDomain'] + ".cert", "w")
            fileCert.write(getVaultItem(certParams['certDomain'], "cert", certParams['vaultServer'], sVaultToken, certParams['vaultKeyName']))
            fileCert.close()
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
        except:
            print "Unexpected error:", sys.exc_info()[0]
    if certParams['saveChain'] == True:
        fileCert = open(certParams['savePath'] + "/" + certDomain + ".cert", "w")
        fileCert.write(getVaultItem(certParams['certDomain'], "chain", certParams['vaultServer'], sVaultToken, certParams['vaultKeyName']))
        fileCert.close()
    if certParams['saveFullChain'] == True:
        fileCert = open(certParams['savePath'] + "/" + certDomain + ".cert", "w")
        fileCert.write(getVaultItem(certParams['certDomain'], "fullchain", certParams['vaultServer'], sVaultToken, certParams['vaultKeyName']))
        fileCert.close()
    if certParams['savePrivKey'] == True:
        fileCert = open(certParams['savePath'] + "/" + certDomain + ".cert", "w")
        fileCert.write(getVaultItem(certParams['certDomain'], "privkey", certParams['vaultServer'], sVaultToken, certParams['vaultKeyName']))
        fileCert.close()
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

def getVaultItem(theCertName, theKey, sVaultServer, sVaultToken, sVaultKey):
    # Valid options for "theKey" are:
    #   cert
    #   fullchain
    #   chain
    #   privkey
    # TODO: If it's not one of those, we should raise an exception

    try:
        vaultClient = hvac.Client(url=sVaultServer, token=sVaultToken)
    except KeyError:
        print("Error: Making connection to vault host: {}".format(sVaultServer))

    theResult = vaultClient.read(sVaultKey + "/" + theCertName)
    if theResult is None:
        raise Exception('Unable to find secret: ' + sVaultKey + "/" + theCertName)
    else:
        try:
            return base64.decodestring(theResult['data'][theKey])
        except KeyError:
            print(theResult)
            raise Exception('Unable to find key in response data from Vault')

    
if __name__ == "__main__":
    main(sys.argv[1:])
