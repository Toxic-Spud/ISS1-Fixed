from tpm2_pytss import *
from tpm2_pytss.types import *
from tpm2_pytss.ESAPI import *
from random import randint

SIGN_KEY_HANDLE = 0x81010000
COM_HANDLE = 0x8101ffff

def generate_ecc_keypair(handle_file):
    with ESAPI() as ctx:

        in_public = TPM2B_PUBLIC.parse("ecc256:ecdsa-SHA256", (TPMA_OBJECT.SIGN_ENCRYPT | TPMA_OBJECT.SENSITIVEDATAORIGIN| TPMA_OBJECT.USERWITHAUTH))

        try:
            # Create the key in the tpm
            primary = ctx.create_primary(
                primary_handle=ESYS_TR.OWNER,
                in_sensitive=TPM2B_SENSITIVE_CREATE(),
                in_public=in_public
            )
            pub = ctx.read_public(primary[0])[0]
            persitant_handle = randint(2164326400, 2164391935)
            # Evict the key to a persistent handle
            ctx.evict_control(ESYS_TR.OWNER, primary[0], persitant_handle)
            ctx.flush_context(primary[0])

            # Save the persistent handle to the file
            print(f"Key created at persistent handle: {hex(persitant_handle)}")
            f = open("signHandle.key", "w")
            f.write(persitant_handle)
            f.close()
            return pub.to_pem()
        except TSS2_Exception as e:
            print(f"Error during key creation: {e}")
            return None



#creates a persistent handle for a com key and returns the publi key
def create_com_key():
    in_public = TPM2B_PUBLIC.parse("ecc256:ecdh",TPMA_OBJECT.DECRYPT|TPMA_OBJECT.SENSITIVEDATAORIGIN|TPMA_OBJECT.USERWITHAUTH)
    ctx = ESAPI()
    primary = ctx.create_primary(TPM2B_SENSITIVE_CREATE(),in_public, ESYS_TR.OWNER)
    persitant_handle = randint(2164326400, 2164391935)
    ctx.evict_control(ESYS_TR.OWNER, primary[0], persitant_handle)
    ctx.flush_context(primary[0])
    f = open("comHandle.key", "w")
    f.write(persitant_handle)
    f.close()
    return primary[1].to_der()






def gen_shared_secret(publicPem:bytes):
    pub = TPM2B_PUBLIC.from_pem(publicPem)
    print(pub.publicArea.unique.ecc.x.buffer.tobytes())
    pub = TPM2B_ECC_POINT(point=pub.publicArea.unique.ecc)#gets the ecc point object from the public key object
    f = open("comHandle.key", "r")
    persistant_handle = f.read()
    f.close()
    ctx = ESAPI()
    keyHandle = ctx.tr_from_tpmpublic(TPM2_HANDLE(persistant_handle))
    secret = ctx.ecdh_zgen(keyHandle, pub)
    return secret



def get_public_key(handle):
    ctx = ESAPI()
    keyHandle = ctx.tr_from_tpmpublic(TPM2_HANDLE(handle))#gets handle to the tpm object
    res = ctx.read_public(keyHandle)[0].to_pem()#reads the public part of the tpm objects and outputs it in pem format
    return res



def remove_persistent_object(handle: int):
    with ESAPI() as ctx:
        tr_handle = ctx.tr_from_tpmpublic(handle)
        ctx.evict_control(ESYS_TR.OWNER, tr_handle, handle)
        print(f"Removed persistent handle: {hex(handle)}")





#function to sign given data
def tpm_sign(data: bytes):
    f = open("signHandle.key", "r")
    handle = int(f.read())
    f.close()
    handle = TPM2_HANDLE(handle)
    ctx = ESAPI()
    key_handle = ctx.tr_from_tpmpublic(handle)
    dig = ctx.hash(data, hash_alg=TPM2_ALG.SHA256)
    sig = ctx.sign(key_handle, dig[0], TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL), validation=dig[1])
    return sig.marshal()


def tpm_verify_signature(marshaledSignature:bytes, signedData:bytes, publicPem):
    pub =TPM2B_PUBLIC.from_pem(publicPem)
    signed = TPMT_SIGNATURE.unmarshal(marshaledSignature)[0]
    try:
        signed.verify_signature(pub, signedData)
        return True
    except:
        return False





""" 
create_com_key()
pub = generate_ecc_keypair("sigPersistant")
pub =TPM2B_PUBLIC.from_pem(pub)
ctx = ESAPI()
sigData = b"signme"
signed = tpm_sign(sigData)
print(signed.verify_signature(pub, sigData))
signed = signed.marshal()
signed = TPMT_SIGNATURE.unmarshal(signed)[0]
print(signed.verify_signature(pub, sigData))


def kdf(data):
    return data


priv1 = ECC.generate(curve="p256")
pub1 = bytes(priv1.public_key().export_key(format="PEM"),"utf-8")
pub2 = ECC.import_key(get_public_key(COM_HANDLE).decode("utf-8"), curve_name="p256")
secret1 = gen_shared_secret(pub1).point.x.buffer
secret2 = DH.key_agreement(static_priv=priv1, kdf=kdf, static_pub=pub2)
print(secret2)
print(bytes(secret1)) """


