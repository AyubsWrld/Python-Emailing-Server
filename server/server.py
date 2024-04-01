# Importing libraries
import socket
from datetime import datetime
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import os

# Setting constant values: Host, Port, the Menu Message
MENUMSG = "Select the operation:\n1) Create and send an email\n2) Display the inbox list\n3) Display the email contents\n4) Terminate the connection\nChoice: "
HOST = '127.0.0.1'
PORT = 13000
# Global variables
sym_key = None
username = None
client_public = None

# Get the server private key from pem file
with open('server_private.pem', 'r') as ServerPrivate:
    SERVER_PRIVATE = RSA.import_key(ServerPrivate.read())

# Generate sym key and encrypt it with the clients public key
def generate_sym(client_public_key):
    global sym_key

    # Generate sym key
    sym_key = os.urandom(32)

    # Ecncrypt sym key with client public key
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    enc_sym_key = cipher_rsa.encrypt(sym_key)
    return enc_sym_key

# Decrypt the data using the servers private key
def decrypt_data_with_privatekey(data):
    # Decrypt data using private key
    cipher = PKCS1_OAEP.new(SERVER_PRIVATE)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data.decode()

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

# Get the clients public_key
def get_client_public_key(username):
    global client_public

    # Get the clients public key using the clients username
    file = f"{username}_public.pem"
    with open(file, 'r') as clientPublic:
        client_public = RSA.import_key(clientPublic.read())

# Validate the client with client information from user_pass.json
def validate(conn):
    global username
    # Send 'Enter Username'
    conn.send('Enter Username: '.encode('utf-8'))
    encrypted_username = conn.recv(1024)
    username = decrypt_data_with_privatekey(encrypted_username)

    # Send 'Enter Password'
    conn.send('Enter Password: '.encode('utf-8'))
    encrypted_password = conn.recv(1024)
    password = decrypt_data_with_privatekey(encrypted_password)

    # Get clients usernames and passwords
    with open('user_pass.json', 'r') as userDatabase:
        data = dict(json.load(userDatabase))
    
    # Check if the clients username and password are in user_pass.json
    if username in data and data[username] == password:
        # If the client is valid, send the encrypted sym key
        get_client_public_key(username)
        enc_sym_key = generate_sym(client_public)
        conn.send(enc_sym_key)
        print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
        return True
    else:
        # If the user is not valid, send invalid message
        invalid_message = bytes("Invalid username or password", 'utf-8')
        conn.send(invalid_message)
        print(f"The received client information: {username} is invalid (Connection Terminated).")
    return False
        
# Add Time and Date information to email
def modify_email(email: str):
    index = email.find("Title")
    # Add 'Time and Date Received' field to email
    time_and_date = f"Time and Date Received: {datetime.now()}\n"
    end_email = email[index:]
    email = email[0:index] + time_and_date + end_email
    return email

# Check if the email title is valid
def valid_email_title(title):
    # Return whether the title is less than or equal to 100 characters
    return len(title) <= 100

# Check if the email content length is valid
def valid_email_content_length(content_length, content):
    # Return whether the content length is equal to the given content_length, and whether its less than 1000000 characters
    return (len(content) == content_length) and (len(content) < 1000000)

# Sending Email Subprotocol
def sending_email_subprotocol(conn):
    # Send email message, encrypted with sym_key
    conn.send(encrypt_data_with_sym("Send the email"))

    # Decrypts recieved email with sym key
    email = decrypt_data_with_sym(conn.recv(1024))

    # Get Sender
    from_sender = email[email.find("From: ") + 6: email.find("To: ") - 1]

    # Get destination clients
    to_dest = email[email.find("To: ") + 4: email.find("Title: ") - 1].split(";")

    # Get email title
    title = email[email.find("Title: ") + 7: email.find("Content Length: ") - 1]

    # Get email content length
    content_length = int(email[email.find("Content Length: ") + 16: email.find("Content: ") - 1])

    # Get email content
    content = email[email.find("Content: ") + 9:]

    # Ensure the email title and content length are valid
    assert valid_email_title(title), "The email title is invalid"
    assert valid_email_content_length(content_length, content), "The email content length is invalid"

    # Remove trailing semi-colon if present
    to_dest[-1] = to_dest[-1][:-1] if to_dest[-1][:-1] == ";" else to_dest[-1]
    recipients = ";".join(to_dest)
    print(f"An email from {from_sender} is sent to {recipients} has a content length of {content_length}.")

    # Add Time and Date information to email
    email = modify_email(email)

    # Add emails in each recipients folder
    for recipient in to_dest:
        title = title.replace(" ", "")
        file = f"./{recipient}/{from_sender}_{title}.txt"
        with open(file, 'w') as e:
            e.write(email)

# Extracts the Time and Date element in the list
def extract_datetime(email_lst):
    return datetime.strptime(email_lst[1], '%Y-%m-%d %H:%M:%S.%f')

# Gets and sorts the clients emails based on Time and Date
def get_sorted_emails():
    # Get all emails in the clients folder
    folder = f"./{username}"
    files = [file for file in os.listdir(folder) if os.path.isfile(os.path.join(folder, file))]
    emails = []
    sorted_emails = []

    # Gets the sender, recipient, and title information for each email in the clients folder
    for file in files:
        file = f"./{username}/{file}"
        with open(file, 'r') as f:
            email = f.read()
        from_sender = email[email.find("From: ") + 6: email.find("To: ") - 1]
        date_time = email[email.find("Time and Date Received: ") + 24: email.find("Title: ") - 1]
        title = email[email.find("Title: ") + 7: email.find("Content Length: ") - 1]
        e = [from_sender, date_time, title]
        emails.append(e)
    
    # Sort the emails based on Time and Date
    sorted_emails = sorted(emails, key=extract_datetime)

    # Sorts it to have earliest emails first
    sorted_emails = sorted_emails[::-1]

    # Indexes all emails, starting from 1
    for i in range(len(sorted_emails)):
        sorted_emails[i].insert(0, str(i+1))
    return sorted_emails

# Viewing Inbox Subprotocol
def viewing_inbox_subprotocol(conn):
    # Header information
    message = "Index    From           DateTime                          Title\n"
    sorted_emails = get_sorted_emails()

    # Adds each emails information to the message
    for email in sorted_emails:
        message += "        ".join(email) + "\n"

    # Send the encrypted message, and waits for ACK
    conn.send(encrypt_data_with_sym(message))
    ack = decrypt_data_with_sym(conn.recv(1024))
    if not (ack == "OK"):
        print("ACK not recieved!")

# Viewing email subprotocol
def viewing_email_subprotocl(conn):
    # Send 'email reaguest index' message
    conn.send(encrypt_data_with_sym("the server request email index"))

    # Decrypt the recieved index
    index = decrypt_data_with_sym(conn.recv(1024))

    # Get the email with the corresponding index
    emails = get_sorted_emails()
    email = emails[int(index) - 1]
    title = email[3]
    title = title.replace(" ", "")
    file = f"./{username}/{username}_{title}.txt"
    with open(file, 'r') as f:
        email = f.read()
    
    # Send the email encrypted with sym key
    conn.send(encrypt_data_with_sym(email))

# Main server function
def start_server():
    # Initialize Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket
    server_socket.bind((HOST, PORT))  # Bind to the port
    server_socket.listen(1)  # Listen for incoming connections
    print("Server started. Listening on port 13000.")

    while True:
        # Accept a new connection
        conn, address = server_socket.accept()
        print(f"Connection from {address} has been established.")

        # Validate client
        user_exists = validate(conn)
        if not user_exists :
            # Close connection is invalid client
            conn.close()
        else:
            # Recieve and decrypt ack
            ack = conn.recv(1024)
            ack = decrypt_data_with_sym(ack)
            if ack == "OK":
                while True:
                    # Send menu message
                    conn.send(encrypt_data_with_sym(MENUMSG))

                    # Recieve anbd decrpyt response
                    response = conn.recv(1024)
                    response = decrypt_data_with_sym(response)
                    if response == '1':
                        # Call Sending Email Subprotocol if choice is 1
                        sending_email_subprotocol(conn)
                    elif response == '2':
                        # Call Viewing Inbox Subprotocol if choice is 2
                        viewing_inbox_subprotocol(conn)
                    elif response == '3':
                        # Call Viewing Email Subprotocol if choice is 3
                        viewing_email_subprotocl(conn)
                    elif response == '4':
                        # Perform Connection Terminal Subprotocol if choice is 4
                        print(f"Terminating connection with {username}.")
                        break
                    
        # Close the connection
        conn.close() 

if __name__ == '__main__':
    start_server()