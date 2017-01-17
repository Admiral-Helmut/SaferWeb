import cipherWhitelist

# Check if a cipher suite is whitelisted ?
if cipherWhitelist.check_cipher("TLS_RSA_WITH_AES_128_GCM_SHA256"):
    print "cipher suite ok"
else:
    print "cipher suite unsecure"