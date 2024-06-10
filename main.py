import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QCompleter, QLabel, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QComboBox
from PyQt5.QtGui import QFont, QColor, QTextCursor, QTextCharFormat, QPixmap
from PyQt5.QtCore import Qt, QTimer, QStringListModel
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import requests
import re
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import padding
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import msgpack
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

staff_data = []
user_id = []
user_secret = []
old_file_sizes = {}
access_tokens = []
public_keys = []
private_keys = []

def get_base64_encoded_public_key(public_key_path): #function for converting the public key into a base64 byte stream appropriate for transmision
    # Read the public key from the PEM file
    with open(public_key_path, 'rb') as file:
        public_key_bytes = file.read()
    # Encode the public key bytes to Base64
    public_key_base64 = base64.b64encode(public_key_bytes).decode('utf-8')

    return public_key_base64

def generate_private_key(client_id, client_secret): #function for generating a private key based the client_id and client_secret.
    # Concatenate username, password to create input data
    input_data = client_id.encode() + client_secret.encode()
    # Derive a key from the input data using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=os.urandom(16),
        iterations=100000,  # Adjust the number of iterations as needed
        backend=default_backend()
    )
    key = kdf.derive(input_data)
    # Generate a private key using RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_public_key(private_key): #function for generating a pbulic key from the private key, using python cryptography library.
    #generate public key
    public_key = private_key.public_key()
    return public_key

def encrypt_access_token(access_token, server_public_key): #function for encrypting the currently held access token.
    #deserialise the bytes form of the public key
    server_public_key = serialization.load_pem_public_key(
        server_public_key,
        backend=default_backend()
    )
    # Encrypt the access token using the public key
    encrypted_access_token = server_public_key.encrypt(
        access_token.encode(),
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_access_token

class CustomCompleterModel(QStringListModel): #function for creating a user role and appending it to a specific row on the complete box, so that clinet IDs are associated with a specific staff member but not visible to the user.
    def __init__(self, data, client_ids, parent=None):
        super().__init__(data, parent)
        self.client_ids = client_ids

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.UserRole:
            return self.client_ids[index.row()]
        return super().data(index, role)

    def setData(self, index, value, role=Qt.EditRole):
        if role == Qt.UserRole:
            self.client_ids[index.row()] = value
            return True
        return super().setData(index, value, role)



class GlyphMainWindow(QWidget): #main dashboard accessible after logging in
    def __init__(self):
        super().__init__()
        pt_server_public_key = ""
        self.current_pthash = None  # Variable to store the latest encountered hash ID
        self.file_sizes = {}
        self.file_size_timer = QTimer()
        self.file_size_timer.setInterval(2000)  # 2 seconds interval
        self.file_size_timer.timeout.connect(self.check_file_sizes)
        self.file_size_timer.start()

        # UI Elements for the main window
        self.setWindowTitle('Glyph - Main Window')
        self.setGeometry(100, 100, 1200, 900) #Set window size to 800x900
        self.setStyleSheet('background-color: #012456;')  # Set background color to hex #012456
        # Left-side layout for Contacts
        left_layout = QVBoxLayout()

        # Connect the timeout signal of the timer to the refresh_access_token every 30 seconds
        self.tokenrefreshtimer = QTimer()
        self.tokenrefreshtimer.start(30000)
        self.tokenrefreshtimer.timeout.connect(self.refresh_access_token)

        # Create a label for displaying greeting message
        self.greetinglabel = QLabel("", self)
        self.greetinglabel.setAlignment(Qt.AlignCenter)
        self.greetinglabel.setGeometry(self.width() / 2 - 190, -25, 200, 200)  # Position at top center with offset
        self.greetinglabel.setStyleSheet("color: white; font-size: 30px;")

        # Create a label for displaying "Clinician:"
        self.stafflabel = QLabel("", self)
        self.stafflabel.setAlignment(Qt.AlignCenter)

        # Create a label for displaying "Patient:"
        self.patientlabel = QLabel("", self)
        self.patientlabel.setAlignment(Qt.AlignCenter)
        self.patientlabel.setGeometry(self.width() / 2 - 240, 500, 300, 100)  # Position at top center with offset
        self.patientlabel.setStyleSheet("color: lightgrey; font-size: 32px;")
        self.patientlabel.setText(f"<i>No Patient Selected.</i>")

        # Create a label for displaying notices/errors related to send_message:
        self.notelabel = QLabel("", self)
        self.notelabel.setAlignment(Qt.AlignCenter)
        self.notelabel.setStyleSheet("color: red; font-size: 16px;")

        # Staff search box
        self.line_edit = QLineEdit(self)
        self.line_edit.setStyleSheet('color: black; font-size: 25px; background-color: white;')
        self.line_edit.setPlaceholderText("Staff Search")  # staff searhc box
        left_layout.addWidget(self.line_edit, alignment=Qt.AlignTop | Qt.AlignLeft)

        # Create and set the completer
        # Create a QStringListModel to hold the completer data
        self.completer_model = QStringListModel()
        self.completer_model = CustomCompleterModel([], [])  # Initialize with empty data
        self.completer = QCompleter(self.completer_model, self.line_edit)
        self.line_edit.setCompleter(self.completer)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchContains)  # Set the filter mode to include partial matches
        self.line_edit.setCompleter(self.completer)
        self.completer.activated.connect(self.add_selected_to_contacts)

         # QTimer to refresh completer every 5 seconds
        self.completer_timer = QTimer(self)
        self.completer_timer.timeout.connect(self.refresh_completer)
        self.completer_timer.start(10000)  # 5000 milliseconds = 5 seconds

        self.conversations_label = QLabel('Conversation', self) #current conversation window
        font_conversations = QFont()
        font_conversations.setPointSize(25)
        self.conversations_label.setFont(font_conversations)
        self.conversations_label.setStyleSheet('color: white;')  # Set text color to white

        # ListWidget for Contacts
        self.contacts_list = QListWidget(self)
        self.contacts_list.setStyleSheet('color: white; font-size: 20px;')

        # Chatbox for Conversations
        self.chatbox = QTextEdit(self)
        self.chatbox.setReadOnly(True)
        self.chatbox.setMinimumWidth(500)
        self.chatbox.setMaximumWidth(500)
        self.chatbox.setStyleSheet('color: white; font-size: 20px;')
        self.message_input = QLineEdit(self)
        self.message_input.setStyleSheet('color: white; font-size: 20px;')
        self.send_button = QPushButton('Send', self)
        self.send_button.clicked.connect(self.send_message)
        self.message_input.returnPressed.connect(self.send_message)
        self.send_button.setStyleSheet('color: white; font-size: 20px; background-color: rgb(0, 100, 200);')
        self.send_button.setFixedHeight(40)

        # Create a QTimer instance
        self.timer = QTimer(self)
        # Connect the QTimer timeout signal to the update_contactlist_items function
        self.timer.timeout.connect(self.update_contactlist_items)
        # Start the timer to trigger every 1 seconds (1000 milliseconds)
        self.timer.start(5000)

        # Layout for the main window
        self.layout = QHBoxLayout(self)


        #left_layout.addWidget(self.contact_list_label, alignment=Qt.AlignTop | Qt.AlignLeft)
        #left_layout.addWidget(self.conversations_combobox, alignment=Qt.AlignTop | Qt.AlignLeft)
        left_layout.addWidget(self.contacts_list)
        self.contacts_list.setMinimumWidth(330)
        self.contacts_list.setMaximumWidth(330)
        self.line_edit.setMinimumWidth(330)
        self.line_edit.setMaximumWidth(330)
        self.layout.addLayout(left_layout)

        # Add stretch to push the Conversation label to the top right
        self.layout.addStretch(1)
        # Right side layout for Conversations
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.conversations_label, alignment=Qt.AlignTop | Qt.AlignRight)
        right_layout.addWidget(self.chatbox)
        right_layout.addWidget(self.message_input)
        right_layout.addWidget(self.send_button)
        self.layout.addLayout(right_layout)
        self.setLayout(self.layout)

        self.contacts_list.itemClicked.connect(self.load_chat_log)

        #self.conversations_combobox.currentIndexChanged.connect(self.location_changed)
        # Create a QTimer instance
        self.chatlogtimer = QTimer()
        # Set the interval to 1000 milliseconds (1 sec)
        self.chatlogtimer.setInterval(1000)
        # Connect the timeout signal of the timer to the load_chat_log function
        self.chatlogtimer.timeout.connect(self.load_chat_log)
        # Start the timer
        self.chatlogtimer.start()

    def refresh_access_token(self):
        if not staff_data:
            return
        client_id = user_id[0]
        # Load the private key from its PEM-encoded representation
        with open(f'{client_id}_private_key.pem', "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # No password protection
            backend=default_backend()
        )
        print("attempting refresh with token", access_tokens[0], user_id[0], user_secret[0])
        public_key_path = f"{client_id}_public_key.pem"
        public_key_base64 = get_base64_encoded_public_key(public_key_path)
        print("public key sent to refresh: ", public_key_base64)
        # Encrypt the access token with the user's public key
        access_token_forrefresh = access_tokens[0]
        server_public_key = public_keys[0]
        encrypted_access_token = encrypt_access_token(access_token_forrefresh, server_public_key)
        #encrypting access token to be sent for refresh using authentication server public key
        encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
        url = 'http://192.168.0.44:5000/oauth/token'
        headers = {'Content-Type': 'application/json'}  # Specify the Content-Type header
        data = {
            'client_id': user_id[0],
            'client_secret': user_secret[0],
            'grant_type': 'refresh_token',
            'refresh_token': encrypted_access_token,
            'user_public_key': public_key_base64
        }
        response = requests.post(url, headers=headers, json=data)  # Send JSON data using the json parameter
        print(response.text)
        if response.status_code == 200:
            token_data = response.json()
            encrypted_access_token = token_data.get('access_token')
            encrypted_token_bytes = base64.b64decode(encrypted_access_token)
            access_token = private_key.decrypt(
                encrypted_token_bytes,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
            access_tokens.clear()
            access_tokens.append(access_token)
            print("decrypted access token: ", access_tokens[0])
            return access_token
        else:
            print('Failed to refresh access token:', response.text)
            return None

    def update_contactlist_items(self): #function to update the contact list with staff member names.
        if not staff_data:
            return
        requester_name_path = user_id[0]
        matching_staff = None
        for staff in staff_data:
            if staff.get('clientID') == user_id[0]:
                matching_staff = staff
        if matching_staff:
            first_name = matching_staff.get('first_name') #creating a greeting with the first name for the current user.
            self.greetinglabel.setText(f"User: <b>{first_name}</b>")
        else:
            self.greetinglabel.setText("Hello Unknown")  # Handle case when no matching staff is found
        resource_server_url = f'http://192.168.0.44:5001/chathistory/{requester_name_path}/'
        response = requests.get(resource_server_url)

        if response.status_code == 200:
            filenames = response.json()  # Assuming the response is JSON containing filenames
            print("contactlist items: ", response.status_code)
            print("constalist list items: ", response.text)
            # Iterate over the retrieved filenames
            for filename in filenames:
                # Find the corresponding staff member data in staff_data
                for staff in staff_data:
                    if staff.get('clientID') == filename:  # Assuming clientID matches filename
                        # Construct the full name and job
                        full_name = f"{staff['first_name']} {staff['last_name']} ({staff['job']})"
                        # Add the full name to the contacts_list with clientID as UserRole
                        staffnameitem = QListWidgetItem(full_name)
                        staffnameitem.setData(Qt.UserRole, staff['clientID'])
                        self.contacts_list.addItem(staffnameitem)
                        break  # Stop searching for staff member once found
        else:
            print("Failed to fetch filenames from the resource server.")

        if staff_data:
            self.timer.stop()

    def send_message(self): #function to send a message to the resource server
        if self.contacts_list.currentItem() is None:
            print("Please select a staff member.")
            self.notelabel.setText(f"<i>No staff member selected.</i>")
            self.notelabel.setGeometry(self.width() / 2 - 120, 795, 200, 50)
            return
        message_text = self.message_input.text().strip()  # Remove leading and trailing whitespaces
        if not message_text:
            print("Empty message.")
            self.notelabel.setText(f"<i>Empty message.</i>")
            self.notelabel.setGeometry(self.width() / 2 - 100, 795, 200, 50)
            return
        if len(self.message_input.text()) > 240:
            print("Message too long.")
            self.notelabel.setGeometry(self.width() / 2 - 100, 795, 200, 50)
            self.notelabel.setText(f"<i>Message too long.</i>")
            return
        self.notelabel.setGeometry(self.width() / 2 - 100, 795, 200, 50)
        self.notelabel.setText(f"")
        url = 'http://192.168.0.44:5001/public-key'
        response = requests.get(url)
        if response.status_code == 200:
            resource_server_public_key = response.json().get('public_key')
            resource_server_public_key = base64.b64decode(resource_server_public_key)
            print("resource server public key:", resource_server_public_key)
        access_token = access_tokens[0]
        encrypted_access_token = encrypt_access_token(access_token, resource_server_public_key)
        encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
        # Get the current date and time
        current_time = datetime.now()
        # Format the current time as a string
        timestamp = current_time.strftime("%Y-%m-%dT%H:%M:%S")
        # Get the selected full name from the contacts_list
        selected_name = self.contacts_list.currentItem()
        # Extract the first 7 characters of the selected name
        client_id = selected_name.data(Qt.UserRole)
        print("Selected name: ", selected_name)
        print("client_ID variable: ", client_id)
        print("user_id: ", user_id[0])
        sendername = 'You'
        for staff in staff_data:
            if staff.get('clientID') == user_id[0]:
                sendername = f"{staff['first_name']} {staff['last_name']}"
        print("sendername:", sendername)
        #Construct the chat log file name based on client_id and selected name prefix
        requester_name_path = user_id[0]
        print(requester_name_path)
        message_content = self.message_input.text()
        if not message_content:
            print("Please enter a message.")
            return
        # Construct the message JSON object
        message = {
                    "sender": sendername,  #
                    "clientID": requester_name_path,  # Y
                    "timestamp": timestamp,  #
                    "content": message_content
                }
        # Convert the JSON message to a string
        message_str = json.dumps(message)
        # Convert the string message to bytes
        message_bytes = message_str.encode('utf-8')
        # Load the public key from bytes
        resource_server_public_key = serialization.load_pem_public_key(
            resource_server_public_key,
            backend=default_backend()
        )
        # Encrypt the message bytes using the RSA public key
        encrypted_message = resource_server_public_key.encrypt(
            message_bytes,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Base64 encode the encrypted message for transmission
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')
        # Construct the URL to send the request to
        resource_server_url = f'http://192.168.0.44:5001/chatlogs/{requester_name_path}/{client_id}'
        headers = {'Authorization': f'Bearer {encrypted_access_token}'}
        # Send the POST request to the resource server with the message JSON data
        response = requests.post(resource_server_url, json=encoded_encrypted_message, headers=headers)
        print("Response send message code:", response.status_code)
        # Check if the request was successful
        if response.status_code == 200:
            print("Message sent successfully!")
            self.message_input.clear()
        else:
            print("Failed to send message. Response Status Code:", response.status_code)
            print("Response Content:", response.text)
            self.message_input.clear()
            self.scroll_position = self.chatbox.verticalScrollBar().maximum()
            self.chatbox.verticalScrollBar().setValue(self.scroll_position)

    def load_chat_log(self): #loading the chat log and filling the chat box. This function is called every second and will also handle communication to the patient details server
        if not staff_data:
            return
        if self.contacts_list.currentItem() is None:
            print("Please select a staff member.")
            return
        client_id = user_id[0]
        # Load the private key from its PEM-encoded representation
        with open(f'{client_id}_private_key.pem', "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  # No password protection
            backend=default_backend()
        )
        print("access token: ", access_tokens[0])
        print("Currently selected pt: ", self.current_pthash)
        client_id = user_id[0]
        public_key_path = f'{client_id}_public_key.pem'
        public_key_base64 = get_base64_encoded_public_key(public_key_path)
        print("public key sent for chat: ", public_key_base64)
        #getting public key for transmission to patient server
        if 'pt_server_public_key' not in locals():
            url = 'http://192.168.0.44:5002/public-key'
            response = requests.get(url)
            if response.status_code == 200:
                server_public_key = response.json().get('public_key')
                pt_server_public_key = base64.b64decode(server_public_key)
                print("pt server public key:", pt_server_public_key)
        # Set the format for highlighting
        format = QTextCharFormat()
        format.setForeground(QColor("blue"))
        # Get a cursor to navigate and modify the text
        cursor = self.chatbox.textCursor()
        cursor.movePosition(QTextCursor.End)
        chatbox_text = self.chatbox.toPlainText()
        # Define the regular expression pattern
        pattern = r'\b\d{3}\s\d{3}\s\d{4}\b'
        regex = re.compile(pattern)
        # Search for patterns like "000 000 0000"
        matches = re.findall(pattern, chatbox_text)
        # Reverse the matches list to start from the bottom of the chatbox
        matches.reverse()
        found_match = False
        for match in matches:
            if match == self.current_pthash:
                if found_match:
                    print("Found CHI unchanged.")
                found_match = True
                break
            if match != self.current_pthash:
                found_match = True
                print("Found CHI:", match)
                self.current_pthash = match
                processed_chi_number = match.replace(' ', '')
                # Calculate SHA-256 hash
                hash_id = hashlib.sha256(processed_chi_number.encode()).hexdigest()
                print("SHA-256 hash:", hash_id)
                access_token = access_tokens[0]
                encrypted_access_token = encrypt_access_token(access_token, pt_server_public_key)
                encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
                headers = {'Authorization': f'Bearer {encrypted_access_token}'}
                url = f'http://192.168.0.44:5002/get_pt_data?hash_id={hash_id}'
                data = {
                    'client_id': user_id[0],
                    'grant_type': 'clinician_token',
                    'user_public_key': public_key_base64
                }
                response = requests.get(url, headers=headers, json=data)
                if response.status_code == 200:
                    encrypted_patient_data = response.json()
                    print("encrypted patient data: ", encrypted_patient_data)#
                    encrypted_patient_data = base64.b64decode(encrypted_patient_data)
                    print("encrypted patient data: ", encrypted_patient_data)#
                    patient_data = private_key.decrypt(
                        encrypted_patient_data,
                        asymmetric_padding.OAEP(
                            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    patient_data = msgpack.unpackb(patient_data)
                    #Extracting data from the patient_data dictionary
                    title = patient_data['Title'].strip()  # Remove leading and trailing whitespace
                    firstname = patient_data['Firstname'].strip()
                    surname = patient_data['Surname'].strip()
                    pt_fullname = f"{title} {firstname} {surname}"
                    # Extracting and formatting CHI
                    chi = str(patient_data['CHI'])
                    pt_CHI = f"{chi[:3]} {chi[3:6]} {chi[6:]}"
                    # Extracting and formatting DOB
                    pt_DOB = patient_data['DOB'].strip()  # Remove leading and trailing whitespace
                    # Extracting address
                    pt_Address = patient_data['Address'].strip()  # Remove leading and trailing whitespace
                    # Printing or using the extracted data
                    print("Full Name:", pt_fullname)
                    print("CHI:", pt_CHI)
                    print("DOB:", pt_DOB)
                    print("Address:", pt_Address)
                    self.patientlabel.setGeometry(self.width() / 2 - 240, 500, 300, 200)  # Position at top center with offset
                    self.patientlabel.setStyleSheet("color: lightgrey; font-size: 24px;")
                    self.patientlabel.setText(
                        f"<i>Current Patient:</i><br><b>{pt_fullname}</b><br>{pt_CHI}<br>\n{pt_DOB}<br>\n{pt_Address}")
                    for match in reversed(list(regex.finditer(chatbox_text))):
                        # Move the cursor to the start of the match
                        cursor.setPosition(match.start())
                        # Move the cursor to the end of the match
                        cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, len(match.group()))
                        # Apply the formatting to the matched text
                        cursor.setCharFormat(format)
                    break
                else:
                    print('Failed to retrieve patient data:', response.text)
                    pt_fullname = ""
                    pt_CHI = ""
                    pt_DOB = ""
                    pt_Address = ""
                    self.patientlabel.setStyleSheet("color: lightgrey; font-size: 32px;")
                    self.patientlabel.setText(f"<i>No Patient Selected.</i>")
                    break
        if not found_match:
            self.current_pthash = "000 000 0000"
            print("No CHI.")
            pt_fullname = ""
            pt_CHI = ""
            pt_DOB = ""
            pt_Address = ""
            self.patientlabel.setStyleSheet("color: lightgrey; font-size: 32px;")
            self.patientlabel.setText(f"<i>No Patient Selected.</i>")

        # Get the selected full name from the contacts_list
        selected_name = self.contacts_list.currentItem()
        selected_name.setForeground(QColor('white'))
        # Extract the user role (clinetID) of the selected name
        client_id = selected_name.data(Qt.UserRole)

        #extract full recipient details for populating central discription panel
        full_name = ""
        full_job = ""
        full_location = ""
        full_email = ""

        for staff in staff_data:
            if staff["clientID"] == client_id:
                full_name = f"{staff['title']} {staff['first_name']} {staff['last_name']}"
                full_job = staff['job']
                full_location = staff['location']
                full_email = staff['email']
        self.stafflabel.setGeometry(self.width() / 2 - 240, 100, 300, 200)  # Position at top center with offset
        self.stafflabel.setStyleSheet("color: lightgrey; font-size: 20px;")
        self.stafflabel.setText(f"<i>Chatting with</i>:<br><b>{full_name}</b><br>{full_job}<br>\n{full_location}<br>\n{full_email}")

        #Construct the chat log file name based on client_id and selected name prefix
        requester_name_path = user_id[0]
        #self.chatbox.clear()
        previous_scroll_position = self.chatbox.verticalScrollBar().value()
        previous_scrollbar_size = self.chatbox.verticalScrollBar().maximum() - self.chatbox.verticalScrollBar().minimum()
        # Clear the chatbox
        self.chatbox.clear()
        # Refill selected chatbox with latest content
        if 'resource_server_public_key' not in locals(): #checking to see if public key is already received from resource server
            url = 'http://192.168.0.44:5001/public-key'
            response = requests.get(url) #getting public key from resource server
            if response.status_code == 200:
                resource_server_public_key = response.json().get('public_key')
                resource_server_public_key = base64.b64decode(resource_server_public_key)
                print("resource server public key:", resource_server_public_key)
        access_token = access_tokens[0] #loading acess tokens
        encrypted_access_token = encrypt_access_token(access_token, resource_server_public_key)
        encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
        headers = {'Authorization': f'Bearer {encrypted_access_token}'}
        resource_server_url = f'http://192.168.0.44:5001/chatlogs/{requester_name_path}/{client_id}'  # resource server URL
        data = {
            'client_id': user_id[0],
            'grant_type': 'clinician_token',
            'user_public_key': public_key_base64
        }
        response = requests.get(resource_server_url, headers=headers, json=data) #sending encrypted access token, sever URL and json data including user's public key.
        chatstaffID = ""
        if response.status_code == 200:            # Parse JSON response
            response_data = response.json()
            encoded_iv = base64.b64decode(response_data['iv'])
            encoded_encrypted_file_contents = base64.b64decode(response_data['encrypted_file_contents'])
            encoded_encrypted_aes_key = base64.b64decode(response_data['encrypted_aes_key'])
            decrypted_aes_key = private_key.decrypt(
                encoded_encrypted_aes_key,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Create an AES-CBC cipher with the provided key and IV
            cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(encoded_iv), backend=default_backend())
            decryptor = cipher.decryptor()
            # Decrypt the encrypted data
            decrypted_data = decryptor.update(encoded_encrypted_file_contents) + decryptor.finalize()
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            # Decode the decrypted data into a string using UTF-8 encoding
            decrypted_json_str = unpadded_data.decode('utf-8')
            # Parse the decrypted JSON string
            json_data = json.loads(decrypted_json_str)
            for message in json_data['messages']:
                sender_name = message['sender']
                timestamp = message['timestamp']
                client_id = message.get('clientID')  # Get clientID from the message
                if client_id == user_id[0]:
                    # Display sender's name and clientID in blue if clientID matches user_id[0]
                    self.chatbox.append(f"<b>{sender_name}</b>")
                else:
                    #Display sender's name and clientID in default color
                 self.chatbox.append(f"<font color='gray'><b>{sender_name}</b></font>")
                self.chatbox.append(f"<i>{timestamp}</i>")
                self.chatbox.append(message['content'])
                self.chatbox.append('')  # Append an empty line for readability
                # Get the current scroll position and scrollbar size after appending messages
                current_scroll_position = self.chatbox.verticalScrollBar().value()
                current_scrollbar_size = self.chatbox.verticalScrollBar().maximum() - self.chatbox.verticalScrollBar().minimum()

                # Check if the scrollbar size has changed (indicating new content)
                if current_scrollbar_size != previous_scrollbar_size:
                    # Scroll to the bottom
                    self.chatbox.verticalScrollBar().setValue(self.chatbox.verticalScrollBar().maximum())
                else:
                    # Preserve the scroll position otherwise
                    self.chatbox.verticalScrollBar().setValue(previous_scroll_position)
        else:
            print("Failed to retrieve patient data from resource server")
            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)
            return None

    def check_file_sizes(self): #checking for changes in file sizes every 2 seconds, as a way to evidence when a new message is received.
        if not staff_data:
            return
        if 'resource_server_public_key' not in locals(): #checking to see if public key is already received from resource server
            url = 'http://192.168.0.44:5001/public-key'
            response = requests.get(url) #getting public key from resource server
            if response.status_code == 200:
                resource_server_public_key = response.json().get('public_key')
                resource_server_public_key = base64.b64decode(resource_server_public_key)
                print("resource server public key:", resource_server_public_key)
        access_token = access_tokens[0] #loading acess tokens
        encrypted_access_token = encrypt_access_token(access_token, resource_server_public_key)
        encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
        # Send GET request to resource server with access token
        headers = {'Authorization': f'Bearer {encrypted_access_token}'}
        requester_name_path = user_id[0]
        resource_server_url = f'http://192.168.0.44:5001/newchats/{requester_name_path}'
        response = requests.get(resource_server_url, headers=headers)

        if response.status_code == 200:
            # Parse the JSON response to extract the file sizes and changes
            data = response.json()
            file_sizes = data.get('file_sizes', {})
            changes = data.get('changes', {})

            # Get the current scroll position
            current_scroll_position = self.chatbox.verticalScrollBar().value() #putting the scrollbar to the bottom of the screen if a new message is received.
            # Check if the current item in contacts_list is the staffnameitem
            current_item = self.contacts_list.currentItem()
            # Iterate over each file in the changes dictionary
            for file_name, change_info in changes.items():
                # Remove .txt extension if present
                file_name_no_extension = file_name.replace('.txt', '')
                # Find the corresponding staffnameitem in the contacts_list
                for index in range(self.contacts_list.count()):
                    staffnameitem = self.contacts_list.item(index)
                    client_id = staffnameitem.data(Qt.UserRole)
                    # Check if the clientID matches the filename (without extension)
                    if current_item == staffnameitem and current_scroll_position == self.chatbox.verticalScrollBar().maximum():
                        continue  # Skip changing text color
                    if client_id == file_name_no_extension:
                        # Change text color to red if file size increased
                        if change_info['increased']:
                            staffnameitem.setForeground(QColor('red'))
                        break

        else:
            print("Failed to retrieve file sizes from the resource server.")
            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

    def refresh_completer(self): #refreshing the completer box (staff search box)
        if not staff_data:
            return
        self.completer_timer.stop()
        completer_strings = []
        client_ids = []
        for staff in staff_data:
            full_name = f"{staff['first_name']} {staff['last_name']} ({staff['job']})"
            completer_strings.append(full_name)
            client_ids.append(staff['clientID'])
        self.completer_model.setStringList(completer_strings)
        self.completer_model.client_ids = client_ids
        model_strings = self.completer_model.stringList()
        print(model_strings)
        for row in range(self.completer_model.rowCount()):
            index = self.completer_model.index(row, 0)
            client_id = self.completer_model.data(index, Qt.UserRole)
            print("Client ID for index", index, ":", client_id)


    def add_selected_to_contacts(self, text): #function for adding a staff member from the selected completer box to the list of contacts.
        # Get the completion text directly from the completer
        completion_text = self.completer.currentCompletion()

        # Check if the completion text already exists in the contacts list
        item_exists = False
        for row in range(self.contacts_list.count()):
            existing_item = self.contacts_list.item(row)
            if existing_item.text() == completion_text:
                item_exists = True
                self.line_edit.clear()
                break

        if not item_exists:
            # Find the corresponding client ID for the completion text
            client_id = None
            for row in range(self.completer_model.rowCount()):
                index = self.completer_model.index(row, 0)
                if self.completer_model.data(index, Qt.DisplayRole) == completion_text:
                    client_id = self.completer_model.data(index, Qt.UserRole)
                    self.line_edit.clear()
                    break

            if client_id is not None:
                # Add the selected item to the contacts list
                staff_name_item = QListWidgetItem(completion_text)
                staff_name_item.setData(Qt.UserRole, client_id)
                self.contacts_list.addItem(staff_name_item)
                self.line_edit.clear()
            else:
                print("Error: Client ID not found for selected item")
                self.line_edit.clear()
        else:
            print("Item already exists in the contacts list")
            self.line_edit.clear()


# Login screen window, the first thing the user will see
class GlyphLoginScreen(QWidget):
    def __init__(self):
        super().__init__()

        # UI Elements for the login window
        self.setWindowTitle('Glyph')
        self.setGeometry(100, 100, 300, 700)
        self.setStyleSheet('background-color: #012456;')

        #Glyph Logo
        pixmap = QPixmap("glyph_logo.png")
        self.image_label = QLabel(self)
        self.image_label.setGeometry(50, 50, 150, 150)
        pixmap = pixmap.scaled(self.image_label.size(), aspectRatioMode=True)
        self.image_label.setPixmap(pixmap)

        # Main header at top of login screen
        self.title_label = QLabel('Glyph\n Chat', self)
        font = QFont('Verlag', 48, QFont.Bold)
        self.title_label.setFont(font)
        self.title_label.setStyleSheet('color: white;')

        # username input field with placeholder text
        self.username_input = QLineEdit(self)
        self.username_input.setFixedHeight(100)
        self.username_input.setPlaceholderText('Username')
        font_username_input = QFont()
        font_username_input.setPointSize(25)
        self.username_input.setFont(font_username_input)
        self.username_input.setStyleSheet('color: white;')

        # password input field with placeholder text
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(100)
        self.password_input.setPlaceholderText('Password')
        font_password_input = QFont()
        font_password_input.setPointSize(25)
        self.password_input.setFont(font_password_input)
        self.password_input.setStyleSheet('color: white;')

        # login button
        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        font_login_button = QFont()
        font_login_button.setPointSize(50)
        self.login_button.setFont(font_login_button)

        # setting colour of the login button to light blue
        light_blue = QColor(0, 100, 200)
        self.login_button.setStyleSheet(f'color: white; background-color: {light_blue.name()};')

        # Additional label for copyright information
        self.copyright_label = QLabel('(C) David Benes 2024', self)
        font_copyright = QFont()
        font_copyright.setPointSize(10)  # Set a smaller text size
        self.copyright_label.setFont(font_copyright)
        self.copyright_label.setStyleSheet('color: white;')  # Set text color to white

        # Additional label for displaying login failure message
        self.error_label = QLabel('', self)
        self.error_label.setFont(font_copyright)
        self.error_label.setStyleSheet('color: red;')  # Set text color to red

        # Reference to the main window
        self.main_window = GlyphMainWindow()

        # Organised layout for the login window
        self.layout = QVBoxLayout()
        self.layout.addWidget((self.image_label), alignment=Qt.AlignCenter)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignCenter)
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)
        self.layout.addWidget(self.error_label)

        # Adjusted spacing to move fields up
        self.layout.setSpacing(10)

        # Added gap at the bottom for copyright text
        self.layout.addStretch()
        self.layout.addWidget(self.copyright_label, alignment=Qt.AlignCenter)
        self.setLayout(self.layout)

    def send_token_request(self, json_data): #function for sending the request for the initial access token using client ID and secret
        token_url = 'http://192.168.0.44:5000/oauth/token'
        headers = {'Content-Type': 'application/json'}  # Specify the Content-Type as 'application/json'
        response = requests.post(token_url, data=json_data, headers=headers)  # Send the request with JSON data and headers
        return response

    def get_clinical_data(self, access_token): #function for retrieving initial clinical data (staff details) from the resource server once the access token has been received.
        if 'resource_server_public_key' not in locals(): #checking to see if public key is already received from resource server
            url = 'http://192.168.0.44:5001/public-key'
            response = requests.get(url) #getting public key from resource server
            if response.status_code == 200:
                resource_server_public_key = response.json().get('public_key')
                resource_server_public_key = base64.b64decode(resource_server_public_key)
                print("resource server public key:", resource_server_public_key)
        access_token = access_tokens[0] #loading acess tokens
        encrypted_access_token = encrypt_access_token(access_token, resource_server_public_key)
        encrypted_access_token = base64.b64encode(encrypted_access_token).decode('utf-8')
        # Send GET request to resource server with access token
        headers = {'Authorization': f'Bearer {encrypted_access_token}'}
        resource_server_url = 'http://192.168.0.44:5001/staffdata'
        response = requests.get(resource_server_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to retrieve patient data from resource server")
            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)
            return None

    def login(self): #login function for when the user initially logs in
        # authentication programming
        client_id = self.username_input.text()
        user_id.clear()
        user_id.append(self.username_input.text())
        client_secret = hashlib.sha256(self.password_input.text().encode()).hexdigest()
        private_key = generate_private_key(client_id, client_secret)
        private_keys.clear()
        private_keys.append(private_key)
        public_key = generate_public_key(private_key)
        # Save or use the private key as needed
        with open(f'{client_id}_private_key.pem', 'wb') as f:
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()  # No encryption for private key
            )
            f.write(private_key_bytes)
        with open(f'{client_id}_public_key.pem', 'wb') as f:
            # Serialize the private key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            f.write(public_key_bytes)
        public_key = base64.b64encode(public_key_bytes).decode('utf-8')
        print("public key: ", public_key)
        print(client_secret)
        user_secret.clear()
        user_secret.append(client_secret)
        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'user_public_key': public_key,
            'grant_type': 'client_credentials'
        }
        json_data = json.dumps(data)  # Convert the dictionary to JSON
        response = self.send_token_request(json_data)  #sending token request using hashed client secret + user public key to authentication server
        print("Response Status Code:", response.status_code)

        if response.status_code == 200:
            try:
                #getting authserver public key in base64 format and decoding to byte stream for use in encrypting.
                server_public_key_base64encoded = response.json().get('authserver_public_key')
                server_public_key = base64.b64decode(server_public_key_base64encoded)
                encrypted_access_token = response.json().get('access_token')
                public_keys.append(server_public_key)
                # Decode the Base64-encoded encrypted access token
                encrypted_token_bytes = base64.b64decode(encrypted_access_token)
                # Load the private key from its PEM-encoded representation
                with open(f'{client_id}_private_key.pem', "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,  # No password protection
                        backend=default_backend()
                    )
                access_token = private_key.decrypt(
                    encrypted_token_bytes,
                    asymmetric_padding.OAEP(
                        mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')
                # Clear the existing access tokens and add the decrypted access token
                access_tokens.clear()
                access_tokens.append(access_token)
                print("encrypted access token: ",encrypted_token_bytes)
                print("access token:", access_token)
                print("access tokens in array", access_tokens[0])
                self.hide()  # Hide the login window
                self.main_window.show()  # Show the main window
                # Send access token to resource server
                clinical_data = self.get_clinical_data(access_token)
                print("clinical data: ", clinical_data)
                clinical_data = self.get_clinical_data(access_token)
                if clinical_data and 'staff' in clinical_data:
                    staff_data.clear()
                    staff_data.extend(clinical_data['staff'])
                    print("Staff data:", staff_data)  # Debugging: Print staff_data
                else:
                    print("No staff data found in clinical data")  # Debugging: Print error message
                return access_token
            except json.decoder.JSONDecodeError:
                print("Failed to decode JSON response")
                print("Response Content:", response.text)
        else:
            print("Failed to get access token")
            print("Response Content:", response.text)
            self.error_label.setText('Login Failed')  # Set error message
            self.error_label.show()  # Show the error label
            self.username_input.clear()
            self.password_input.clear()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_screen = GlyphLoginScreen()
    login_screen.show()
    sys.exit(app.exec_())
