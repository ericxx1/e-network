import uuid
import rsa
from rsa import *
import base64
import aes
publickey, privatekey = rsa.newkeys(1024)
print publickey
print privatekey

aeskey = str(uuid.uuid4().hex) # Generate new AES Key
key = encrypt(aeskey, eval(str(publickey))) # Encrypt AES key with target's RSA Public Key
key = base64.b64encode(key)
msg = raw_input("Enter Msg to encrypt:")
msg = aes.encryptData(aeskey,msg) # Encrypt Message with AES Key
msg = base64.b64encode(msg) # Base64 encode the message
print "Your msg encrypted via your public key: " + msg
aeskey = decrypt(base64.b64decode(key), privatekey)
uncrypted=aes.decryptData(aeskey, base64.b64decode(msg)).encode("utf-8")
print "Your msg decrypted via your private key:" + uncrypted
