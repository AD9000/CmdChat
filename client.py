import socket

def welcome():
    print("Welcome to the CmdMessaging app. Finally you get to talk to your friends through the best UI ever: The command line! *Fireworks in background*")
    
def login():
    print("Enter your username")
    username = input()
    print("Enter your password")
    password = input()


if __name__ == "__main__":
    welcome()
    while (not login()):
        pass