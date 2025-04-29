import argon2
import hashlib
from os import urandom
from Crypto.Cipher import ChaCha20_Poly1305
from os import urandom
from Crypto.PublicKey import ECC
from hkdf import hkdf_expand as h_exp, hkdf_extract as h_ext
import hashlib
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import DSS
import json
import base64
from Crypto.Hash import SHA256, HMAC
from datetime import datetime
from tpm import *

def slow_client_hash(password, username):
    saltGenerator = hashlib.sha256()#use username as salt
    saltGenerator.update(bytes(username, "utf-8"))
    userSalt = saltGenerator.digest()
    hasher = argon2.PasswordHasher(10, 256000, 4,64,32)#high argon2 parameters stop shucking
    hashedPassword = hasher.hash(password, salt=userSalt)
    return(hashedPassword)


def check_cert(cert):
    caPublicKey = ECC.import_key(open("TrustedRoot.txt", "r").read(), curve_name="p256")
    verif = DSS.new(caPublicKey, "fips-186-3")
    cert = json.loads(cert)
    if (cert["subject"] != "Finance Company ltd" or cert["issuer"] != "Simulated CA" 
        or datetime.strptime(cert["notBefore"], "%Y-%m-%d") > datetime.now() 
        or datetime.strptime(cert["notAfter"], "%Y-%m-%d") < datetime.now() 
        or "subjectPublicKey" not in cert): return False
    sig = base64.b64decode(cert.pop("signature"))
    hash = SHA256.new(bytes(json.dumps(cert), "utf-8"))
    try:
        verif.verify(hash, sig)
        return True
    except:
        return False


def encrypt_msg(plaintext:bytes, key:bytes):
    nonce = urandom(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def decrypt_msg(ciphertext:bytes, key:bytes):
    nonce = ciphertext[:12]
    tag = ciphertext[-16:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext[12:-16], tag)
        return plaintext
    except:
        return("Message failed integrity check")
    


def encrypt_chacha20(plaintext, key, nonce, sequenceNumber, header):
    nonce = bytes(abyte ^ bbyte for abyte, bbyte in zip(nonce, sequenceNumber.to_bytes(12, 'big')))
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = header + nonce + ciphertext + tag
    return payload


def decrypt_chacha20(ciphertext, key, expectedNonce):
    header = ciphertext[:4]
    nonce = ciphertext[4:16]
    if nonce != expectedNonce:
        raise ValueError("Recieved message with incorrect sequence number")
    tag = ciphertext[-16:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext[16:-16], tag)
    except ValueError as e:
        print("Communication tampered with connection terminating")
        raise e
    return plaintext




#wrapper to ensure that sha256 is used for HKDF
def hkdf_extract(key, salt):
    result = h_ext(salt, key, hashlib.sha256)
    return result

#wrapper to ensure that sha256 is used for HKDF
def hkdf_expand(key, info, length=32):
    result = h_exp(key, info, length, hashlib.sha256)
    return result


def  hkdf_expand_label( key, info, transcript_hash, length=32):
    HKDFLabel = int(256).to_bytes(2,"big") + b"tls13" +info+ transcript_hash
    result = hkdf_expand(key, HKDFLabel, length)
    return(result)

# empty kdf as TLS1.3 keyshedule will be used and key agreement implementation requires a KDF
def empty_kdf(input):
    return input





def get_handshake_keys(sharedSecret, transcript):
    handShakeSecret = hkdf_extract(sharedSecret, b"")
    clientShakeSecret = hkdf_expand_label(handShakeSecret, b"c hs traffic", transcript, 32)#derive handshake secrets
    serverShakeSecret = hkdf_expand_label(handShakeSecret, b"s hs traffic", transcript, 32)
    clientShakeKey = hkdf_expand_label(clientShakeSecret, b"key", b"", 32)#deriving hadshake keys
    clientShakeIV = hkdf_expand_label(clientShakeSecret, b"iv", b"", 12)
    serverShakeKey = hkdf_expand_label(serverShakeSecret, b"key", b"", 32)
    serverShakeIV = hkdf_expand_label(serverShakeSecret, b"iv", b"", 12)
    return((handShakeSecret,(clientShakeKey, clientShakeIV), (serverShakeKey, serverShakeIV), (clientShakeSecret, serverShakeSecret)))




def client_hello(connection):
    hello = []
    random = urandom(32)
    clientPriv = ECC.generate(curve="Curve25519")
    hello.append(random)
    hello.append(clientPriv.public_key().export_key(format="raw"))
    connection.send_hello(hello)
    return (random, clientPriv)


def verify_signature(sig, pub, transcript):
    signedData = bytes("TLS 1.3, server CertificateVerify", "utf-8") + b"\x00" + transcript
    verified = tpm_verify_signature(sig, signedData, pub)
    return verified
    verifier = DSS.new(pub, "fips-186-3")
    try:
        verifier.verify(signedData, sig)
        return True
    except:
        return False
    
def get_finished_keys(secrets):
    clientFinishedKey = hkdf_expand_label(secrets[0],b"finished",b"", 32)
    serverFinishedKey = hkdf_expand_label(secrets[1],b"finished",b"", 32)
    return (clientFinishedKey, serverFinishedKey)


def send_finished(connection, key, transcript):
    hashMac = HMAC.new(key, transcript, SHA256).digest()
    connection.send_finish(hashMac)

def verify_finished(hashMac, key, transcript):
    verifier = HMAC.new(key, transcript, SHA256)
    try:
        verifier.verify(hashMac)
        return(True)
    except:#verify throws error if invalid
        return(False)#return false if in valid

def get_application_secrets(handshakeSecret, transcript):
    derived = hkdf_expand_label(handshakeSecret, b"derived", b"", 32)
    masterSecret = hkdf_extract(b"", derived)
    clientAppSecret = hkdf_expand_label(masterSecret, b"c ap traffic", transcript, 32)
    serverAppSecret = hkdf_expand_label(masterSecret, b"s ap traffic", transcript, 32)
    return((clientAppSecret,serverAppSecret))


def handshake(connection):
    random, clientPriv = client_hello(connection)#sends hello and storres the private section of the key pair
    transcriptHash = hashlib.sha256()#create transcript hash
    serverHello = connection.read_handshake()#get the server hello
    serverPub = ECC.import_key(encoded=(b'0*0\x05\x06\x03+en\x03!\x00'+serverHello[1]), curve_name="Curve25519")#import server public key
    transcriptHash.update(random)
    transcriptHash.update(clientPriv.public_key().export_key(format="raw"))
    transcriptHash.update(serverHello[0])
    transcriptHash.update(serverHello[1])#added client hello and server hello to transcript hash
    sharedSecret = key_agreement(eph_priv=clientPriv, eph_pub=serverPub, kdf=empty_kdf, static_priv=None, static_pub=None)#use ECDH to obtain shared secret
    handshakeData = get_handshake_keys(sharedSecret, transcriptHash.digest())#get handshake keys
    connection.set_keys(handshakeData[1], handshakeData[2])#set the keys used by the connection object to encrypt and decrypt data
    cert = connection.read_handshake()[0].decode("utf-8")#get the certificate sent by server
    transcriptHash.update(bytes(cert, "utf-8"))#add certificate to the transcript hash
    try:
        validCert = check_cert(cert)#checks certificate against public keys in the applications trusted root
    except:
        validCert = False #if check cert throws an error set valid cert to false
    if not validCert:#if certificate isn't valid close connection and raise an error
        print("Server Sent Invalid Certificate Connection Terminated")
        connection.close()
        raise ValueError("Invalid Certificate")
    cert = json.loads(cert)
    serverPub = bytes(cert["subjectPublicKey"], "utf-8")#extract the public key from the certificate
    verifySig = connection.read_handshake()[0]#get the verify certificate message
    if not verify_signature(verifySig, serverPub, transcriptHash.digest()):
        connection.close()
        raise ValueError("Invalid Signature")#if the signature in the verify certificate fails close connection and throw an error
    transcriptHash.update(verifySig)#add verify cert to transcript hash
    finishedKeys = get_finished_keys(handshakeData[3])#get keys for client finished
    serverFinished = connection.read_handshake()[0]#get the server finished message
    if not verify_finished(serverFinished, finishedKeys[1],transcriptHash.digest()):#verifies server finished using finished keys
        connection.close()
        raise ValueError("Finished message failed validation")#throws error if verification fails
    transcriptHash.update(serverFinished)#adds server finished to transcript hash
    send_finished(connection, finishedKeys[0], transcriptHash.digest())#creates and sends client finished
    appSecrets = get_application_secrets(handshakeData[0],transcriptHash.digest())#derives application traffic secrets
    connection.set_secrets(appSecrets[0], appSecrets[1])#sets the secrets stored in the connection object 
    connection.keys_from_secrets()#derives keys from the secrets in the connection object 
    print(connection.get_message())#should recieve successful handshake from the server
    return 
