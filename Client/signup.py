from ClientCrypto import slow_client_hash
from communicate import Communicate
from TotpSetup import get_qrcode, show_qr_code
import os






def sign_up():
    reply = None
    while reply != b"success":
        print("SIGN UP")
        userN = str(input("Enter username: "))
        passW = str(input("Enter password: "))
        passConf = str(input("Enter Password Confirmation: "))
        if passW != passConf:
            print("Passwords do not match")
        else:
            pHash = slow_client_hash(passW, userN)
            data = [userN, pHash.split("$")[5]]
            print(data)
            Communicate.send("sign", data)
            reply = Communicate.read_reply()
            if reply[0] == "totp":
                secret = reply[1]
                qrcode_img = get_qrcode(secret, userN)
                show_qr_code(qrcode_img)
                break
    del passW
    del passConf
    return(True)




