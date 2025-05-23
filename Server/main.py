from communicate import Communicate
from actions import *

class user:
    def __init__(self, username):
        self.username = username
        self.publicKeys
        self.role

def main():
    cont = "continue"
    connection = Communicate()
    while cont == "continue":
        try:
            connection.accept()
            connection.initiate_handshake()
            while True:
                data = connection.get_message()
                if data is None:
                    break
                if data[0] == "sign":
                    print("signing up")
                    sign_up(connection, data[1].decode("utf-8"), data[2].decode("utf-8"), data[3], data[4]) #change these defaults when in production
                elif data[0] == "clog":
                    login(connection, data[1], data[2], data[3])
                elif data[0] == "stok":
                    get_stocks(connection, data[1].decode("utf-8"))
                elif data[0] == "tran":
                    transaction(connection, data[1], data[2], data[3], data[4], data[7], data[5], data[6])
                elif data[0] == "hist":
                    get_history(connection, data[-1:][0].decode("utf-8"), int(data[1]))
                elif data[0] == "getm":
                    if len(data) > 2:
                        get_messages(connection, data[-1:][0].decode("utf-8"), int(data[1].decode("utf-8")))
                    else:
                        get_messages(connection, data[-1:][0].decode("utf-8"))
                elif data[0] == "emps":
                    employee_sign_up(connection, data[1].decode("utf-8"), data[2].decode("utf-8"), data[3].decode("utf-8"), data[4], data[5])
                elif data[0] == "logo":
                    logout(connection, data[1].decode("utf-8"))
                elif data[0] == "nemp":
                    add_employee(connection, data[1].decode("utf-8"), data[3].decode("utf-8"), data[2].decode("utf-8"))
                elif data[0] == "lusr":
                    get_users(connection, data[1].decode("utf-8"))
                elif data[0] == "asig":
                    assign_employee_to_customer(connection, int(data[1].decode("utf-8")), int(data[2].decode("utf-8")), data[3].decode("utf-8"))
                elif data[0] == "smsg":
                    if len(data) > 3:
                        send_msg(connection, data[1], data[-1:][0].decode("utf-8"), int(data[2].decode("utf-8")))
                    else:
                        send_msg(connection, data[1], data[-1:][0].decode("utf-8"))
                elif data[0] == "lcus":
                    get_assigned(connection, data[-1:][0].decode("utf-8"))
                elif data[0] == "acti":
                    activate(connection, data[1].decode("utf-8"), data[-1:][0].decode("utf-8"))
                elif data[0] == "deac":
                    deactivate(connection, data[1].decode("utf-8"), data[-1:][0].decode("utf-8"))            
                elif data[0] == "glog":
                    get_logs(connection, data[-1:][0].decode("utf-8"))
                elif data[0] == "back":
                    backup(connection, data[-1:][0].decode("utf-8"))
                elif data[0] == "revk":
                    if len(data) > 3:
                        revoke_key(connection, data[-1:][0].decode("utf-8"),data[1].decode("utf-8"),data[2].decode("utf-8"))
                    else:
                        revoke_key(connection, data[-1:][0].decode("utf-8"),data[1].decode("utf-8"))
                elif data[0] == "skey":
                    set_key(connection, data[-1:][0].decode("utf-8"), data[1].decode("utf-8"), data[2].decode("utf-8"), data[3])
                else:
                    connection.send("fail", ["400"])
        except Exception as e:
            print(f"{e}")
            connection.close()
            connection.bind()

main()