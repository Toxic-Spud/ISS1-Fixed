from ClientCrypto import slow_client_hash
from ClientCrypto import slow_client_hash, hkdf_extract, encrypt_msg,  decrypt_msg, empty_kdf
from TotpSetup import get_qrcode, show_qr_code
from communicate import Communicate
import json
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Protocol import DH
from Crypto.Hash import SHA256
from os import urandom
from base64 import b64encode, b64decode
#from tpm import tpm_sign, gen_shared_secret
from datetime import datetime

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
            connection.sessionId = reply[1].decode("utf-8")
            return(json.loads(reply[2].decode("utf-8")))
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
    signKey = ECC.generate(curve="p256")
    comKey = ECC.generate(curve="p256")
    while reply != b"success":
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
            data = [userN, pHash.split("$")[5], comKey.public_key().export_key(format="DER"), signKey.public_key().export_key(format="DER")]
            connection.send("sign", data)
            reply = connection.get_message()
            if reply[0] == "totp":
                sFile = open("sealedSign.key", "bw")
                cFile = open("sealedCom.key", "bw")
                sFile.write(signKey.export_key(format="DER"))
                cFile.write(comKey.export_key(format="DER"))
                cFile.close()
                sFile.close()
                secret = reply[1]
                qrcode_img = get_qrcode(secret, userN)
                show_qr_code(qrcode_img)
                break
            print(reply[1])
    del passW
    del passConf
    return(True)


def get_stocks(connection:Communicate):
    connection.send("stok", [], "id")
    stocks = connection.get_message()
    if stocks[0] !="fail":
        stocks = stocks[1:]
        print_table([bytes(json.dumps(("ID","PRICE", "NAME")), "utf-8")] + stocks)
    else:
        print(stocks[1].decode("utf-8"))
    return 



def transaction(connection:Communicate, user, action):
    account = str(user["id"])
    stock = None
    amount = None
    stock = str(input("Enter the desired stock ID"))
    amount = str(input("Enter number of stocks to purchase (must be integer)"))
    key = ECC.import_key(open("sealedSign.key", "rb").read(), curve_name="p256")
    id = b64encode(urandom(32)).decode("utf-8")
    sig = DSS.new(key, "fips-186-3").sign(SHA256.new(bytes(account + stock + amount + action + str(user["id"])+id, "utf-8")))
    connection.send("tran", [account, stock, amount, action, sig, id], "sessionId")
    response = connection.get_message()
    if response[0] == "fail":
        print(f"Transaction failed {response[1]}")
    else:
        print("Transaction Completed")
    return


def get_history(connection:Communicate, account_id):
    connection.send("hist", [str(account_id)], "id")
    history = connection.get_message()
    if history[0] =="succ":
        history = history[1:]
        print_table(history)
    else:
        print(history[1].decode("utf-8"))
    return 
        


def add_employee(connection:Communicate):
    username = str(input("Enter the username for new employee"))
    connection.send("nemp", [username], "sessionId")
    result = connection.get_message()
    if result[0] == "succ":
        print(f"Employee added code {result[1].decode('utf-8')} can be used by employee to sign up (code is valid for 1 week)")




def assign_customer(connection:Communicate):
    choice = None
    while choice != "b":
        print("Assigning customer to finance officer (enter b for back)")
        employee = str(input("Enter emplyee ID: ")).lower()
        customer = str(input("Enter customer ID: ")).lower()
        if customer == "b" or employee == "b":
            return
        connection.send("asig", [employee, customer], "sessionId")
        reply = connection.get_message()
        print(reply[1])
        if reply[0] == "succ":
            return



def print_table(table):
    colWidth = []
    for row in table:
        row = json.loads(row.decode("utf-8"))
        for i, item in enumerate(row):
            item = str(item)
            if len(colWidth) < len(table[0]):
                colWidth.append(len(item))
            elif len(item) > colWidth[i]:
                colWidth[i] = len(item)
    for row in table:
        printRow = ""
        row = json.loads(row.decode("utf-8"))
        for i, item in enumerate(row):
            item = str(item)
            if i != 0:
                printRow += "| " 
            printRow += str(item) + " "*((colWidth[i]+1) - len(item))
        print(printRow)


def get_users(connection:Communicate):
    connection.send("lusr", [], "sessionId")
    employees = connection.get_message()
    columns = [json.dumps(["Id", "Username", "Role"])]
    if employees[0] == "succ":
        print_table(columns+employees[1:])



def revoke_key(connection:Communicate):
    response = ""
    while response.lower() != "b":
        print("\nRevoke user's  Signature Public Key (sign)\nRevoke user's communications Public Key(com)\nRevoke and rekey the database(data)\nRevoke servers current cert and generate new certificate (cert)")
        response = str(input("Enter Choice: ")).lower()
        if response == "data" or response == "cert":
            connection.send("revk", [response], "sessionId")
        elif response == "sign" or response == "com":
            target =  str(input("Enter Id of the User: ")).lower()
            connection.send("revk", [response, target], "sessionId")
        reply = connection.get_message()
        print(reply[1])
        if reply[0] == "succ":
            return
    return





def backup_rekey_database(connection:Communicate):
    connection.send("back", [], "sessionId")
    print(connection.get_message()[1])
    return
    





def get_messages(connection:Communicate, length=0):
    connection.send("getm", [], "sessionId")
    reply = connection.get_message()
    if reply[0] == "fail":
        print(f"Failed to retrieve messages {reply[1]}")
        raise Exception("Failed to get messages")
    pubKey = reply[1]
    if reply[1] == b"None":
        print("You do not have a financial advisor please contact adminsistrator to get one")
        raise ValueError("No Financial advisor")
    privKey = ECC.import_key(open("sealedCom.key", "br").read(), curve_name="p256")
    secret  = DH.key_agreement(static_priv=privKey, static_pub=pubKey, kdf=empty_kdf)
    #secret = gen_shared_secret(pubKey) TODO
    secretKey = hkdf_extract(secret, b"msg")
    msgs = reply[2:]
    if len(msgs) <= length:#skips costly decryption if no new messages since last call
        return secretKey, None
    decryptedMessages = []
    for msg in msgs:
        msg = msg.decode("utf-8")
        msg = json.loads(msg)
        encMsg = b64decode(msg[1])
        decMsg = decrypt_msg(encMsg, secretKey)
        decryptedMessages.append(decMsg.decode("utf-8"))
    return secretKey, decryptedMessages
    


def messages(connection:Communicate, userId):
    try:
        secretKey, decryptedMessages = get_messages(connection)
    except:
        return
    print_messages(decryptedMessages, userId)
    choice = None
    while choice != "b":
        print("Send message (s)\nView messages again (v)\nBack (b)")
        choice = str(input("Enter Choice: ")).lower()
        if choice == "s":
            newMessage = str(input("Enter message: "))
            send_message(connection, newMessage, secretKey, userId)
        elif choice == "v":
            try:
                secretKey, res = get_messages(connection, len(decryptedMessages))
                if not res:
                    print_messages(decryptedMessages)
                else:
                    print_messages(res)
            except:
                pass
    return



def print_messages(messages, currentUserId):
    for message in messages:
        message = json.loads(message)
        messageRows = []
        while message[1] != "":
            messageRows.append(message[1][:20])
            message[1] = message[1][20:]
        for row in messageRows:
            if str(message[0]) != str(currentUserId):
                print(" "*30+str(row))
            else:
                print(str(row))
    


def send_message(connection:Communicate, content:str, key:bytes, userId:str|int):
    message = [str(content), str(userId), datetime.now().strftime("%D/%m/%Y %H:%M")]
    message = bytes(json.dumps(message), "utf-8")
    message = encrypt_msg(message, key)
    connection.send("smsg", [message])
    reply = connection.get_message()
    if  reply[0] != "succ":
        print(f"Failed to send msg: {reply[1]}")
        return
    else:
        print("Message sent successfully")
        return

    