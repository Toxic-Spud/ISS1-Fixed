from communicate import Communicate
from time import sleep
from actions import *
def reconnect(connection):
    sleep(0.5) #wait before reconnect
    


def main():
    connection = Communicate()
    connection.initiate_handshake()
    choice = ''
    user = None
    while choice != 'q':
        try:
            if not user:
                print("\n\nWelcome to Finance Incorporated!")
                print("------------------------------------------")
                print("Sign up (s)\nLog in (l)\nEmployee Sign up (e)")
                print("------------------------------------------")
                choice = input("Enter s, l or e: ").strip().lower()
                if choice == 's':
                    sign_up(connection)
                elif choice == 'l':
                    user = log_in(connection)
                    print(user)
                elif choice == "e":
                    employee_sign_up(connection)
                else:
                    print("Invalid choice")
            elif user["role"] == "customer":
                print("\n\n------------------------------------------")
                print(f"View available stocks (stks) \nBuy Stocks (buy)\nSell Stocks (sell)\nSee History (hist) \nSee\\send messages(msg)\nLogout (log)")
                print("------------------------------------------")
                choice = input("Enter choice: ").strip().lower()
                if choice.lower() == "stks":
                    get_stocks(connection)
                elif choice.lower() == "sell":
                    transaction(connection, user, "s")
                elif choice.lower() == "buy":
                    transaction(connection, user, "b")
                elif choice.lower() == "hist":
                    get_history(connection, user["id"])
                elif choice.lower() == "msg":
                    customer_messages(connection, user["id"])
                elif choice =="log":
                    logout(connection)
                    user = None
            elif user["role"] == "finance advisor":
                print("\n\n------------------------------------------")
                print(f"View available stocks (stks) \nView assigned customers (ls cus)\nBuy Stocks (buy)\nSell Stocks (sell)\nSee History (hist) \nSee\\send messages(msg)\nLogout (log)")
                print("------------------------------------------")
                choice = input("Enter choice: ").strip().lower()
                if choice.lower() == "stks":
                    get_stocks(connection)
                elif choice.lower() == "sell":
                    employee_transaction(connection, "s")
                elif choice.lower() == "buy":
                    employee_transaction(connection, "b")
                elif choice.lower() == "hist":
                    employee_get_history(connection)
                elif choice.lower() == "msg":
                    employee_messages(connection, user["id"])
                elif choice =="log":
                    logout(connection)
                    user = None
                elif choice =="ls cus":
                    get_customers(connection)
            else:
                print("\n\n------------------------------------------")
                print(f"Logout (out)")
                print("Add employee (new)\nList Users (ls usr)\nAssign customer to finance advisor (asig)\nGet Logs (log)\nBackup database (back)\nRevoke Key (revk)")
                print("Activate User (actv),\nDeactivate User (deac)")
                print("------------------------------------------")
                choice = input("Enter choice: ").strip().lower()
                if choice =="out":
                    confirmation = logout(connection)
                    user = None
                elif choice =="new":
                    add_employee(connection)
                elif choice =="ls usr":
                    get_users(connection)
                elif choice =="asig":
                    assign_customer(connection)
                elif choice =="log":
                    get_logs(connection)
                elif choice =="back":
                    backup_rekey_database(connection)
                elif choice =="revk":
                    revoke_key(connection)
                elif choice =="actv":
                    activate(connection)
                elif choice =="deac":
                    deactive(connection)
                
        except Exception as e:
            print(e)
            connection.close()
            sleep(0.1)
            connection.connect()
            connection.initiate_handshake()


    connection.close()
    print("Goodbye!")



main()


