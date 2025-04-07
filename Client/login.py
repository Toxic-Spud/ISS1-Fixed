from ClientCrypto import slow_client_hash
from communicate import Communicate


def log_in():
    reply = None
    while True:
        print("LOG IN")
        userN = str(input("Enter username: "))
        passW = str(input("Enter password: "))
        pHash = slow_client_hash(passW, userN)
        totp = str(input("Enter TOTP: "))
        data = [userN, pHash.split("$")[5],totp]
        Communicate.send("clog", data)
        reply = Communicate.read_reply()
        if reply[0] == "success":
            print(reply[1])
            break
        print(reply[1])
    del passW
    del pHash
    del totp
    del data
    return(True)


