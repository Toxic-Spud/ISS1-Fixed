from communicate import Communicate
from time import sleep
from actions import log_in, sign_up, get_stocks, transaction, get_history, messages, employee_sign_up, logout, add_employee, get_users, assign_customer

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
                print("Welcome to Finance Tracker!")
                print("Sign up (s)\nLog in (l)\nEmployee Sign up (e)")
                print("Enter s, l or e: ")
                choice = input().strip().lower()
                if choice == 's':
                    sign_up(connection)
                elif choice == 'l':
                    user = log_in(connection)
                    print(user)
                elif choice == "e":
                    employee_sign_up(connection)
                else:
                    print("Invalid choice. Please enter 's' for sign up or 'l' for log in.")
            else:
                print(f"View available stocks (st) \nBuy Stocks (b)\nSell Stocks (se)\nSee History (h) \nSee\\send messages(m)\nLogout (log)")
                print("Add employee (new)\nList Users (l)\nAssign customer to finance advisor (asig)")
                choice = input("Enter choice: ").strip()
                if choice.lower() == "st":
                    get_stocks(connection)
                elif choice.lower() == "se":
                    transaction(connection, user, "s")
                elif choice.lower() == "b":
                    transaction(connection, user, "b")
                elif choice.lower() == "h":
                    get_history(connection, user["id"])
                elif choice.lower() == "m":
                    messages(connection, user["id"])
                elif choice =="log":
                    confirmation = logout(connection)
                    if confirmation:
                        user = None
                elif choice =="new":
                    add_employee(connection)
                elif choice =="l":
                    get_users(connection)
                elif choice =="asig":
                    assign_customer(connection)
        except Exception as e:
            print(e)
            connection.close()
            sleep(0.1)
            connection.connect()
            connection.initiate_handshake()


    connection.close()
    print("Goodbye!")



main()


