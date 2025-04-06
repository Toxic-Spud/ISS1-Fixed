import argon2
import hashlib
import random 
from datetime import datetime

def slow_client_hash(password, username):
    saltGenerator = hashlib.sha256()
    saltGenerator.update(bytes(username, "utf-8"))
    userSalt = hashlib.sha256().digest()
    hasher = argon2.PasswordHasher(10, 256000, 4,64,32)
    hashedPassword = hasher.hash(password, salt=userSalt)
    return(hashedPassword)











