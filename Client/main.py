from communicate import Communicate
from time import sleep
from actions import log_in, sign_up, get_stocks, transaction, get_history, messages

def reconnect(connection):
    sleep(0.5) #wait before reconnect
    


def main():
    connection = Communicate()
    connection.initiate_handshake()
    choice = ''
    user = None
    while choice != 'e':
        try:
            if not user or choice == "log":
                print("Welcome to Finance Tracker!")
                print("Sign up (s) or Log in (l)")
                print("Enter s or l: ")
                choice = input().strip()
                if choice == 's':
                    sign_up(connection)
                elif choice == 'l':
                    user = log_in(connection)
                    print(user)
                else:
                    print("Invalid choice. Please enter 's' for sign up or 'l' for log in.")
            else:
                print(f"View available stocks (st) \nBuy Stocks (b)\nSell Stocks (se)\nSee History (h) \nSee\\send messages(m)\nLogout (log)\n")
                choice = input().strip()
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
        except Exception as e:
            print(e)
            connection.close()
            sleep(0.1)
            connection.connect()
            connection.initiate_handshake()


    connection.close()
    print("Goodbye!")



main()


