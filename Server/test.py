from communicate import Communicate
from os import urandom
from Crypto.PublicKey import ECC
from hkdf import hkdf_expand as h_exp, hkdf_extract as h_ext
import hashlib
from Crypto.Protocol.DH import key_agreement
CON = Communicate()
CON.accept()


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
    secrets = {}
    keys = {}
    handShakeSecret = hkdf_extract(sharedSecret, b"")
    clientShakeSecret = hkdf_expand_label(handShakeSecret, b"c hs traffic", transcript, 32)
    serverShakeSecret = hkdf_expand_label(handShakeSecret, b"s hs traffic", transcript, 32)
    clientShakeKey = hkdf_expand_label(clientShakeSecret, b"key", b"", 32)
    clientShakeIV = hkdf_expand_label(clientShakeSecret, b"iv", b"", 12)
    serverShakeKey = hkdf_expand_label(serverShakeSecret, b"key", b"", 32)
    serverShakeIV = hkdf_expand_label(serverShakeSecret, b"iv", b"", 12)
    return((handShakeSecret,(clientShakeKey, clientShakeIV), (serverShakeKey, serverShakeIV)))


def server_hello(connection):
    hello = []
    random = urandom(32)
    clientPriv = ECC.generate(curve="Curve25519")
    hello.append(random)
    hello.append(clientPriv.public_key().export_key(format="raw"))
    connection.send_hello(hello)
    return (random, clientPriv)



def handshake(connection):
    transcriptHash = hashlib.sha256()
    try:
        clientHello = connection.read_handshake()
    except Exception as e:
        connection.close()
        raise e
    random, serverPriv = server_hello(connection)
    clientPub = ECC.import_key(encoded=(b'0*0\x05\x06\x03+en\x03!\x00'+clientHello[1]), curve_name="Curve25519")#extra bytes added to conform raw public key to DER format
    transcriptHash.update(clientHello[0])
    transcriptHash.update(clientHello[1])
    transcriptHash.update(random)
    transcriptHash.update(serverPriv.public_key().export_key(format="raw"))
    sharedSecret = key_agreement(eph_priv=serverPriv, eph_pub=clientPub, kdf=empty_kdf, static_priv=None, static_pub=None)
    handshakeData = get_handshake_keys(sharedSecret, transcriptHash.digest())
    print(handshakeData)
    return


handshake(CON)