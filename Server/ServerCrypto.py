import argon2
from os import urandom

from hkdf import hkdf_expand as h_exp, hkdf_extract as h_ext
from hkdf import hmac
from database import AUTH_DATA_BASE
from log import ALERT_LOGGER
from cryptography import x509

import base64
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.DH import key_agreement
import hashlib
import json
from datetime import datetime, timedelta


CA = ECC.import_key(b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 9\x04R\xc4\xc7\x81\xd6\x06\xee\xd7\xcf`\x92\x8d\xed\xe5\x9eHj\xa2\x8a\xa8\xbc\x8b\xdb7bJ\xec@\x99;\xa1D\x03B\x00\x04\xff\xeb\x91\x18\xe89g\xadWR\xf5\xb8\x86%\x1bt1\xb1\xbfs\xdd\x11\xe1\xb2p\x17\x84\x1f\xf9<DMc)\xc8\x94(S\xac\xbf\x01\xeb\xad\xd6\xc1`#\xff:B\x9fG6\xed\xba\x94FmI\x00\xde\xf3?\xd2')
CA_PUB = CA.public_key()
caSig = DSS.new(CA, "fips-186-3")

def create_certificate(subject:str, notBefore:str, notAfter:str,  subjectPublicKey:str):
    cert = {"issuer": "Simulated CA", "subject": subject, "notBefore": notBefore, "notAfter": notAfter, "subjectPublicKey": subjectPublicKey}
    sig = caSig.sign(SHA256.new(bytes(json.dumps(cert), "utf-8")))
    cert["signature"] = str(base64.b64encode(sig))[2:-1]
    return json.dumps(cert)



def check_cert(cert):
    verif = DSS.new(CA_PUB, "fips-186-3")
    cert = json.loads(cert)
    sig = base64.b64decode(cert.pop("signature"))
    hash = SHA256.new(bytes(json.dumps(cert), "utf-8"))
    try:
        verif.verify(hash, sig)
        return True
    except: 
        return False



PRIVATE_KEY = ECC.generate(curve="p256")
SIGN = DSS.new(PRIVATE_KEY, "fips-186-3")
PUBLIC_KEY = PRIVATE_KEY.public_key().export_key(format="PEM")
CERTIFICATE = create_certificate("Finance Company ltd", str((datetime.now()-timedelta(days=1)).date()), str((datetime.now()+timedelta(days=(365*5))).date()), PUBLIC_KEY)

#wrapper to ensure that sha256 is used for HKDF
def hkdf_extract(key, salt):
    result = h_ext(salt, key, hashlib.sha256)
    return result

#wrapper to ensure that sha256 is used for HKDF
def hkdf_expand(key, info, length=32):
    result = h_exp(key, info, length, hashlib.sha256)
    return result


def  hkdf_expand_label( key, info, transcript_hash, length=32):
    HKDFLabel = bytes(256) + b"tls13" +info+ transcript_hash
    result = hkdf_expand(key, HKDFLabel, length)
    return(result)

# empty kdf as TLS1.3 keyshedule will be used and key agreement implementation requires a KDF
def empty_kdf(input):
    return input



def get_handshake_keys(sharedSecret, transcript):
    handShakeSecret = hkdf_extract(sharedSecret, b"")
    clientShakeSecret = hkdf_expand_label(handShakeSecret, b"c hs traffic", transcript, 32)
    serverShakeSecret = hkdf_expand_label(handShakeSecret, b"s hs traffic", transcript, 32)
    clientShakeKey = hkdf_expand_label(clientShakeSecret, b"key", b"", 32)
    clientShakeIV = hkdf_expand_label(clientShakeSecret, b"iv", b"", 12)
    serverShakeKey = hkdf_expand_label(serverShakeSecret, b"key", b"", 32)
    serverShakeIV = hkdf_expand_label(serverShakeSecret, b"iv", b"", 12)
    return((handShakeSecret,(clientShakeKey, clientShakeIV), (serverShakeKey, serverShakeIV), (clientShakeSecret, serverShakeSecret)))




def verify_signature(sig, pub, signedData):
    pub = ECC.import_key(pub, curve_name="p-256")
    signedData = SHA256.new(bytes(signedData, "utf-8"))
    verifier = DSS.new(pub, "fips-186-3")
    try:
        verifier.verify(signedData, sig)
        return True
    except:
        return False



def server_hello(connection):
    hello = []
    random = urandom(32)
    clientPriv = ECC.generate(curve="Curve25519")
    hello.append(random)
    hello.append(clientPriv.public_key().export_key(format="raw"))
    connection.send_hello(hello)
    return (random, clientPriv)


def verify(connection, transcript):
    signedData = SHA256.new(bytes("TLS 1.3, server CertificateVerify", "utf-8") + b"\x00" + transcript)
    signature = SIGN.sign(signedData)
    connection.send_verify(signature)
    return signature



def get_finished_keys(secrets):
    clientFinishedKey = hkdf_expand_label(secrets[0],b"finished",b"", 32)
    serverFinishedKey = hkdf_expand_label(secrets[1],b"finished",b"", 32)
    return (clientFinishedKey, serverFinishedKey)


def send_finished(connection, key, transcript):
    hashMac = HMAC.new(key, transcript, SHA256).digest()
    connection.send_finish(hashMac)
    return hashMac

def verify_finished(hashMac, key, transcript):
    verifier = HMAC.new(key, transcript, SHA256)
    try:
        verifier.verify(hashMac)
        return(True)
    except:
        return(False)

def get_application_secrets(handshakeSecret, transcript):
    derived = hkdf_expand_label(handshakeSecret, b"derived", b"", 32)
    masterSecret = hkdf_extract(b"", derived)
    clientAppSecret = hkdf_expand_label(masterSecret, b"c ap traffic", transcript, 32)
    serverAppSecret = hkdf_expand_label(masterSecret, b"s ap traffic", transcript, 32)
    return((clientAppSecret,serverAppSecret))


def handshake(connection):
    transcriptHash = hashlib.sha256()
    try:
        clientHello = connection.read_handshake()
    except Exception as e:
        connection.close()
        raise e
    random, serverPriv = server_hello(connection)
    clientPub = ECC.import_key(encoded=b'0*0\x05\x06\x03+en\x03!\x00'+clientHello[1], curve_name="Curve25519")
    transcriptHash.update(clientHello[0])
    transcriptHash.update(clientHello[1])
    transcriptHash.update(random)
    transcriptHash.update(serverPriv.public_key().export_key(format="raw"))
    sharedSecret = key_agreement(eph_priv=serverPriv, eph_pub=clientPub, kdf=empty_kdf, static_priv=None, static_pub=None)
    handshakeData = get_handshake_keys(sharedSecret, transcriptHash.digest())
    connection.set_keys(handshakeData[2], handshakeData[1])
    transcriptHash.update(bytes(CERTIFICATE, "utf-8"))
    connection.send_cert(CERTIFICATE)
    verSig = verify(connection, transcriptHash.digest())
    transcriptHash.update(verSig)
    finishedKeys = get_finished_keys(handshakeData[3])
    finishMsg = send_finished(connection, finishedKeys[1], transcriptHash.digest())
    transcriptHash.update(finishMsg)
    appSecrets = get_application_secrets(handshakeData[0],transcriptHash.digest())
    clientFinish = connection.read_handshake()[0]
    if not verify_finished(clientFinish, finishedKeys[0], transcriptHash.digest()):
        connection.close()
        raise ValueError("Invalid client Finished")
    connection.set_secrets(appSecrets[1], appSecrets[0])
    connection.keys_from_secrets()
    connection.send("succ", ["handshake sucessfully established"])
    return






def encrypt_chacha20(plaintext, key, nonce, sequenceNumber, header):
    nonce = bytes(abyte ^ bbyte for abyte, bbyte in zip(nonce, sequenceNumber.to_bytes(12, 'big')))
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = header + nonce + ciphertext + tag
    return payload


def decrypt_chacha20(ciphertext, key, expectedNonce):
    header = ciphertext[:2]
    nonce = ciphertext[2:14]
    if nonce != expectedNonce:
        raise ValueError("Recieved message with incorrect sequence number")
    tag = ciphertext[-16:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext[14:-16], tag)
    except ValueError as e:
        ALERT_LOGGER.warn("Message authentication failed possibly tampered")
        raise e
    return plaintext



def new_TOTP(username):
    if username == None:
        raise Exception("Username is None")
    secret = urandom(32)
    secret = base64.b32encode(secret)
    AUTH_DATA_BASE.add_secret(username, secret)
    return(secret.decode("utf-8"))



def new_password(clientPassHash:str):
    hasher = argon2.PasswordHasher()
    hashedPassword = hasher.hash(clientPassHash)
    return(hashedPassword)


def get_pass (username):
    passW = AUTH_DATA_BASE.get_user_password(username)
    if passW == None:
        raise Exception("User doesn't exist")
    return(passW)


def check_pass(username, password):
    currentPass = get_pass(username).decode("utf-8")
    try:
        authenticate = argon2.PasswordHasher().verify(currentPass, password)
        return authenticate
    except:
        return False








