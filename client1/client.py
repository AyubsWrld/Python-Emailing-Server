import socket
import json
import os
import datetime
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os

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
    with open(file, 'r') as ClientPrivate:
        client_private = RSA.import_key(ClientPrivate.read())

# Check if the email title is valid
def valid_email_title(title):
    return len(title) <= 100

# Check if the email content is valid
def valid_email_content(content_length, content):
    return (len(content) == content_length) and (len(content) < 1000000)

# Format the email correctly, with the email data
def format_email(sender, recipients, title, content_length, content):
    return f"From: {sender}\nTo: {recipients}\nTitle: {title}\nContent Length: {content_length}\nContent: {content}"

# Get SYM_KEY by decrypting enc_sym_key with private key
def get_sym_key(enc_sym_key, private_key):
    # Decrypt the symmetric key with the client's private RSA key
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    sym_key = cipher_rsa.decrypt(enc_sym_key)
    return sym_key

# Encrypt the data with the servers public key
def encrypt_with_serverpublic(data):
    cipher = PKCS1_OAEP.new(SERVER_PUBLIC)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

# Encrypts the data using the sym_key
def encrypt_data_with_sym(data):
    # Ensure the symmetric key (AES key) is 256 bits (32 bytes)
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")

    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Pad the data and encrypt
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data

# Decrypts the data using the sym key
def decrypt_data_with_sym(data):
    # Ensure the symmetric key is 256 bits (32 bytes)
    if len(sym_key) != 32:
        raise ValueError("Symmetric key must be 256 bits (32 bytes) long")

    # Create an AES cipher object in ECB mode
    cipher = AES.new(sym_key, AES.MODE_ECB)

    # Decrypt the data and unpad
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data.decode()

# Decrypt data using the private key
def decrypt_data_with_privatekey(data):
    cipher = PKCS1_OAEP.new(client_private)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

# Validate the client
def validate(conn):
    global sym_key, username
    # Send username and password
    message = conn.recv(1024).decode('utf-8') 
    username = input(message)
    enc_username = encrypt_with_serverpublic(username)
    conn.send(enc_username)

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
        get_client_private_key(username)
        sym_key = decrypt_data_with_privatekey(ack)
        conn.send(encrypt_data_with_sym("OK"))
        return True

# Sending email subprotocol
def sending_email_subprotocol(conn):
    # Decrypt send email message
    send_email_msg = decrypt_data_with_sym(conn.recv(1024))
    if send_email_msg == "Send the email":
        destination_clients = input("Enter destinations (separated by ;): ").split(';')
        email_title = input("Enter title: ")
        load_content = input("Would you like to load contents from a file?(Y/N) ")
        if load_content.upper() == "Y":
            message_content = input("Enter filename: ")
            with open(message_content, 'r') as file:
                message_content = file.read()
        else:
            message_content = input("Enter message contents: ")
        email = f"From: {username}\nTo: {destination_clients}\nTitle: {email_title}\nContent Length: {len(message_content)}\nContent: {message_content}"
        conn.send(encrypt_data_with_sym(email))
        print("The message is sent to the server.")



# Viewing inbox subprotocol
def viewing_inbox_subprotocol(conn):
    pass

# Viewing email subprotocol
def viewing_email_subprotocl(conn):
    pass

# Main client function
def client():
    host = '127.0.0.1' # Server's IP address
    port = 13000  # The same port as the server

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    client_socket.connect((host, port))  # Connect to the serverA

    validation_state = validate(client_socket)
    if validation_state:
        while True:
            menu = decrypt_data_with_sym(client_socket.recv(1024))
            print(menu)
            choice = input("Choice: ")
            client_socket.send(encrypt_data_with_sym(choice))
            if choice == '1':
                sending_email_subprotocol(client_socket)
            elif choice == '2':
                viewing_inbox_subprotocol(client_socket)
            elif choice == '3':
                viewing_email_subprotocl(client_socket)
            elif choice == '4':
                print("The connection is terminated with the server.")
                break
    client_socket.close()  # Close the connection

if __name__ == '__main__':
    client()