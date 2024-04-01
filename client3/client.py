# Importing libraries
import socket
import json
import os
import datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os

# Global Variables
sym_key = None
client_private = None
username = None

# Get the server public key
with open('server_public.pem', 'r') as ServerKey:
    SERVER_PUBLIC = RSA.import_key(ServerKey.read())

# Get the client private key
def get_client_private_key(username):
    global client_private
    file = f"{username}_private.pem"

    # Import the client private key from pem file
    with open(file, 'r') as ClientPrivate:
        client_private = RSA.import_key(ClientPrivate.read())

# Check if the email title is valid
def valid_email_title(title):
    # Return whether the title is less than or equal to 100 characters
    return len(title) <= 100

# Check if the email content length is valid
def valid_email_content_length(content_length, content):
    # Return whether the content length is equal to the given content_length, and whether its less than 1000000 characters
    return (len(content) == content_length) and (len(content) < 1000000)

# Get sym key by decrypting encoded sym key with client private key
def get_sym_key(enc_sym_key, private_key):
    # Decrypt the sym key with the client's private RSA key
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    sym_key = cipher_rsa.decrypt(enc_sym_key)
    return sym_key

# Encrypt the data with the servers public key
def encrypt_with_serverpublic(data):
    cipher = PKCS1_OAEP.new(SERVER_PUBLIC)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

# Encrypts the data using the sym key
def encrypt_data_with_sym(data):
    # Ensure the symmetric key (AES key) length is 256 bits
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")
    
    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Pad the data and encrypt using sym key
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data

# Decrypts the data using the sym key
def decrypt_data_with_sym(data):
    # Ensure the symmetric key length is 256 bits
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")
    
    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Decrypt the data using sym key and unpad
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data.decode()

# Decrypt the data using the clients private key
def decrypt_data_with_privatekey(data):
    # Decrypt data using private key
    cipher = PKCS1_OAEP.new(client_private)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

# Validate the client
def validate(conn):
    global sym_key, username

    # Send encrypted username
    message = conn.recv(1024).decode('utf-8') 
    username = input(message)
    enc_username = encrypt_with_serverpublic(username)
    conn.send(enc_username)

    # Send encrypted password
    message = conn.recv(1024).decode('utf-8') 
    password = input(message)
    password = encrypt_with_serverpublic(password)
    conn.send(password)

    # Recieve ACK
    ack = conn.recv(1024)
    if ack == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        return False
    else:
        # Get the client private key
        get_client_private_key(username)

        # Decrypt encoded sym key to get sym key
        sym_key = decrypt_data_with_privatekey(ack)

        # Send encrypted "OK"
        conn.send(encrypt_data_with_sym("OK"))
        return True

# Sending Email Subprotocol
def sending_email_subprotocol(conn):
    # Decrypt send email message
    send_email_msg = decrypt_data_with_sym(conn.recv(1024))
    if send_email_msg == "Send the email":
        # Ask client for recipients
        destination_clients = input("Enter destinations (separated by ;): ")

        # Ask client for email title
        email_title = input("Enter title: ")

        # Ask client whether to load email contents from file
        load_content = input("Would you like to load contents from a file?(Y/N) ")
        if load_content.upper() == "Y":
            # Get email contents from file
            email_content = input("Enter filename: ")
            with open(email_content, 'r') as file:
                email_content = file.read()
        else:
            # Get email contents from client input
            email_content = input("Enter message contents: ")

        # Determine content length
        content_length = len(email_content)

        # Ensure the email title and content length are valid
        assert valid_email_title(email_title), "The email title is invalid"
        assert valid_email_content_length(content_length, email_content), "The email content length is invalid"
        
        # Format and send the encrypted email
        email = f"From: {username}\nTo: {destination_clients}\nTitle: {email_title}\nContent Length: {content_length}\nContent: {email_content}"
        conn.send(encrypt_data_with_sym(email))
        print("The message is sent to the server.")

# Viewing Inbox Subprotocol
def viewing_inbox_subprotocol(conn):
    # Get and decrypt inbox
    inbox = decrypt_data_with_sym(conn.recv(1024))
    print(inbox)

    # Send encryped "OK"
    conn.send(encrypt_data_with_sym("OK"))

# Viewing Email Subprotocol
def viewing_email_subprotocl(conn):
    # Decrypt 'email index request' message
    message = decrypt_data_with_sym(conn.recv(1024))
    if message == "the server request email index":
        # Ask client for index
        index = input("Enter the email index you wish to view: ")

        # Send encrypted index
        conn.send(encrypt_data_with_sym(index))

        # Recieve, decrypt, and display email
        email = decrypt_data_with_sym(conn.recv(1024))
        print("\n", email, "\n", sep="")
        
# Main client function
def client():
    # Ask user to input Server Ip or Name
    host = input("Enter the server IP or name: ") # Server's IP address: '127.0.0.1'
    port = 13000  # The same port as the server

    # Initialize socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    client_socket.connect((host, port))  # Connect to the serverA

    # Validate client
    validation_state = validate(client_socket)
    if validation_state:
        while True:
            # Receive, decrypt, and display options menu
            menu = decrypt_data_with_sym(client_socket.recv(1024))
            print(menu, end="")

            # Ask client for choice, encrypt it, and send it
            choice = input("")
            client_socket.send(encrypt_data_with_sym(choice))
            if choice == '1':
                # Call Sending Email Subprotocol if choice is 1
                sending_email_subprotocol(client_socket)
            elif choice == '2':
                # Call Viewing Inbox Subprotocol if choice is 2
                viewing_inbox_subprotocol(client_socket)
            elif choice == '3':
                # Call Viewing Email Subprotocol if choice is 3
                viewing_email_subprotocl(client_socket)
            elif choice == '4':
                # Perform Connection Terminal Subprotocol if choice is 4
                print("The connection is terminated with the server.")
                break
            
    # Close the connection
    client_socket.close()

if __name__ == '__main__':
    client()