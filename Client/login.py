from ClientCrypto import slow_client_hash
from ClientCrypto import slow_client_hash
from TotpSetup import get_qrcode, show_qr_code
from communicate import Communicate



def log_in(connection:Communicate):
    reply = None
    retry = 'y'
    while retry.lower() != 'n':
        print("LOG IN")
        userN = str(input("Enter username: "))
        passW = str(input("Enter password: "))
        pHash = slow_client_hash(passW, userN)
        totp = str(input("Enter TOTP: "))
        data = [userN, pHash.split("$")[5],totp]
        connection.send("clog", data)
        reply = connection.get_message()
        if reply[0] == "succ":
            return(reply[1])
        print(reply[1].decode("utf-8"))
    return None





def pass_req(password:str, confPass:str):
    if password == None or "":
        return "Password cannot be empty"
    if len(password) < 16:
        return "Password must be at least 16 characters"
    if len(password) > 128:
        return "Password must be less than 128 characters"
    if password != confPass:
        return "Password and confirmation do not match"
    if password.isalnum():
        return "Password must contain at least 1 special character"
    if password.islower():
        return "Password must contain at least 1 uppercase character"
    if password.isupper():
        return "Password must contain at least 1 lowercase character"
    if password.isdigit():
        return "Password must contain at least 1 uppercase and lowwercase letter"
    return True




def sign_up(connection):
    reply = None
    while reply[0] != "totp":
        print("SIGN UP")
        print("Password must have >15 characters and <128 charactershave at least 1 uppercase, 1 lowercase, 1 number and 1 special character and be unique")
        print("Username must be >6 characters")
        userN = str(input("Enter username: "))
        passW = str(input("Enter password: "))
        passConf = str(input("Enter Password Confirmation: "))
        msg = pass_req(passW, passConf)
        if len(userN) < 6:
            print("Username must exceed 6 characters")
        elif pass_req(passW, passConf) != True:
            print(msg)
        else:
            pHash = slow_client_hash(passW, userN)
            data = [userN, pHash.split("$")[5]]
            connection.send("sign", data)
            reply = connection.get_message()
            if reply[0] == "totp":
                secret = reply[1]
                qrcode_img = get_qrcode(secret, userN)
                print("Scan QR code with google authenticator")
                show_qr_code(qrcode_img)
            print(reply[1])
    del passW
    del passConf
    return(True)