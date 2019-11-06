from socket import *
import sys
import signal

class Client():
    def __init__(self):
        #Server would be running on the same host as Client
        serverName = sys.argv[1]
        serverPort = int(sys.argv[2])

        # Socket
        clientSocket = socket(AF_INET, SOCK_STREAM)

        # Signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

    def welcome(self):
        print("Welcome to CmdChat. Finally you get to talk to your friends through the best UI ever: The command line! *Fireworks in background*")
        
    def login(self):
        print("Enter your username")
        username = input()
        print("Enter your password")
        password = input()
        message = username + " " + password

        # Try to log the user in:
        response = sendDataToServer(message)
        
    def sendDataToServer(self, message):
        # Send message to the server
        clientSocket.sendto(message.encode(), (self.serverName, self.serverPort))

        #wait for the reply from the server
        receivedMessage, serverAddress = clientSocket.recvfrom(2048)
        return receivedMessage

    def signal_handler(self, sig, frame):
        self.endClient()
        sys.exit(0)

    def endClient(self):
        # Close the socket
        clientSocket.close()    

    
if __name__ == "__main__":
    client = Client()
    client.loop()