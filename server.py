import os
import socket
import time
import json


#---------------------------------------------------- Menu message --------------------------------------------------------
MENUMSG = "1) Create and send an email\n2) Display the inbox list\n3) Display the email conents\n4) Terminate the connection"
#---------------------------------------------------- Menu message --------------------------------------------------------


#---------------------------------------------------- Messages index to retrieve the one you want --------------------------------------------------------

MESSAGES = [
    "Enter the server IP or name: ",
    "Enter your username: ",
    "Enter your password: ",
]

#---------------------------------------------------- Messages index to retrieve the one you want --------------------------------------------------------

def validate(conn): #Also handles the menu msg?  
    #Send Server IP
    conn.send(MESSAGES[0].encode('utf-8'))  # Send response to the client
    servername = conn.recv(1024).decode('utf-8') 
    #Send enter Username
    conn.send(MESSAGES[1].encode('utf-8'))  # Send response to the client
    username = conn.recv(1024).decode('utf-8') 
    #Send Enter Password
    conn.send(MESSAGES[2].encode('utf-8'))  # Send response to the client
    password = conn.recv(1024).decode('utf-8')  
    #Store credentials in tuple 
    credentials = (servername, username, password)
    with open('user_pass.json' , 'r') as userDatabase : 
        data = json.load(userDatabase)
    
    user_exists  = False 
    for i in data: 
        if i == username :
            if password == data[i]:
                user_exists  = True
                break
    conn.send(str(user_exists).encode('utf-8'))
    return user_exists , username

#---------------------------------------------------- Messages index to retrieve the one you want ----------------------------------


#---------------------------------------------------- Gets Choice from user --------------------------------------------------------

def getChoice(socket):
    choice = socket.recv(1024).decode('utf-8') 
    return choice

#---------------------------------------------------- Gets Choice from user --------------------------------------------------------


def handleOne(socket): 
    PROMPTS = ['Enter destinations (seprated by ;) ',
               'Enter title: ',
               'Would you like to load contents from a file?(Y/N): ',
               'Enter filename: ',
               'The message is sent to the server']
    socket.send(PROMPTS[0].encode('utf-8'))
    response = socket.recv(1024).decode()
    print(response)

    socket.send(PROMPTS[1].encode('utf-8'))
    response = socket.recv(1024).decode()
    print(response)

    socket.send(PROMPTS[2].encode('utf-8'))
    response = socket.recv(1024).decode()
    print(response)

    socket.send(PROMPTS[3].encode('utf-8'))
    response = socket.recv(1024).decode()
    print(response)

def handleThree(socket):
    MESSAGE = "Enter the email index you wish to view: "
    socket.send(MESSAGE.encode('utf-8'))

    response = socket.recv(1024).decode()
    print(response)


#---------------------------------------------------- Handles communication loop until 4 entered -----------------------------------
def handleComms(socket): 
    socket.send(MENUMSG.encode('utf-8'))
    choice = getChoice(socket)
    continue_connection = True
    while continue_connection : 
        if choice == '1':
            handleOne(socket)
            socket.send(MENUMSG.encode('utf-8'))
            choice = getChoice(socket)

        elif choice == '2' : 
            print("Hello") 
            socket.send(MENUMSG.encode('utf-8'))
            choice = getChoice(socket)

        elif choice == '3' : 
            handleThree(socket)
            socket.send(MENUMSG.encode('utf-8'))
            choice = getChoice(socket)


        elif choice == '4' :
            print("Connection Terminated") 
            continue_connection = False

        else: 
            choice = getChoice(socket)

#---------------------------------------------------- Handles communication loop until 4 entered --------------------------------------------------------

def send(socket): 
    recipients = socket.recv(1024).decode('utf-8')
    recipients = recipients.split(';')
    print(recipients) 
    values

#---------------------------------------------------- Overarching server prototype --------------------------------------------------------

def start_server():
    host = '127.0.0.1'
    port = 13000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    server_socket.bind((host, port))  # Bind to the port
    server_socket.listen(1)  # Listen for incoming connections

    print("Server started. Listening on port 13000.")

    while True:
        conn, address = server_socket.accept()  # Accept a new connection
        nTuple = validate(conn)  # Returns tuple with username and whether the user exists or not  (Boolean , Username)
        user_exists = nTuple[0]
        if not user_exists : 
            ERRORMSG = "Invalid username or password\nConnection terminating"
            print(f"The recieved information: {nTuple[1]} is invalid")
            conn.send(ERRORMSG.encode('utf-8'))
            conn.close()
        else:
            print(f"Connection Accepted and Symmetric key generated for: {nTuple[1]}")
            handleComms(conn)

        conn.close()  # Close the connection
        break

#---------------------------------------------------- Overarching server prototype --------------------------------------------------------

if __name__ == '__main__':
    start_server()

