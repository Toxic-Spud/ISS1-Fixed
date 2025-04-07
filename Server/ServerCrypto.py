import argon2
from os import urandom
import base64
from database import AUTH_DATA_BASE





def new_TOTP(username):
    if username == None:
        raise Exception("Username is None")
    secret = AUTH_DATA_BASE.get_user_secret(username)
    print(secret)
    if secret[0] != None:
        raise Exception("User already has a TOTP secret")
    secret = urandom(32)
    secret = base64.b32encode(secret)
    AUTH_DATA_BASE.add_secret(username, secret)
    return(secret.decode("utf-8"))



def new_password(clientPassHash):
    hasher = argon2.PasswordHasher()
    hashedPassword = hasher.hash(clientPassHash)
    return(hashedPassword)


def get_pass (username):
    passW = AUTH_DATA_BASE.get_user_password(username)
    if passW == None:
        raise Exception("User doesn't exist")
    return(passW)


def check_pass(username, password):
    currentPass = get_pass(username)
    return(argon2.PasswordHasher().verify(currentPass, password))








