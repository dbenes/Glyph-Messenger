from flask import Flask, request, jsonify, send_file
import io
import base64
from cryptography.fernet import Fernet
import pandas as pd
import jwt
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import msgpack




app = Flask(__name__) #Flask is used for all the servers, a framewokrk for handling web applications that use HTTP such as OAuth 2.0

ptserver_private_key = rsa.generate_private_key( #creating a pprivate key
    public_exponent=65537,
    key_size=2048,
)
ptserver_public_key = ptserver_private_key.public_key() #creating a public key

with open('ptserver_private_key.pem', 'wb') as f: #saving the private key to a local .pem file
    # Serialize the private key
    ptserver_private_key_bytes = ptserver_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    f.write(ptserver_private_key_bytes)
with open('ptserver_public_key.pem', 'wb') as f: #saving the public key to a local .pem file
    # Serialize the private key
    ptserver_public_key_bytes = ptserver_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(ptserver_public_key_bytes)

print(ptserver_private_key_bytes)
print(ptserver_public_key_bytes)

ptserver_public_key = base64.b64encode(ptserver_public_key_bytes).decode('utf-8') #encodning the public key using base64 encoding

## Secret key used to sign and verify JWT tokens
SECRET_KEY = "f4b3b8e99f43d4565ed7724a54585bde06d604f10daea12555f3b9a0a9f20e8"  # Replace with a secure secret key

# Load the encryption key
def load_key():
    with open('encryption_key.key', 'rb') as f:
        return f.read()

# Decrypt the patients.xlsx.encrypted file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as f:
        data = f.read()
    decrypted_data = fernet.decrypt(data)
    return decrypted_data

def get_patient_data(hash_id, decrypted_data): #function for retreiving the patient data fom the unencrypted xlsx file
    # Convert decrypted bytes to a binary stream
    binary_stream = io.BytesIO(decrypted_data)
    # Read Excel file from the binary stream
    df = pd.read_excel(binary_stream)
    # Find the row with the matching HashID
    patient_record = df[df['HashID'] == hash_id]
    if not patient_record.empty:
        return patient_record.to_dict(orient='records')[0]
    else:
        return None

# Function to encrypt data using Fernet
def encrypt_data(data, secret_key):
    # Initialize Fernet cipher with the provided secret key
    cipher = Fernet(secret_key)
    # Encrypt the data
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

@app.route('/public-key', methods=['GET']) #public endpoint for distributing public key.
def get_public_key():
    return jsonify({'public_key': ptserver_public_key})

@app.route('/get_pt_data', methods=['GET'])
def get_patient_data_endpoint():
    # Check if the request includes a valid access token
    data = request.json
    access_token = request.headers.get('Authorization')
    user_public_key = data.get('user_public_key')
    user_public_key = base64.b64decode(user_public_key)
    user_public_key = serialization.load_pem_public_key(user_public_key, backend=default_backend())

    if not access_token or not access_token.startswith('Bearer '):
        return jsonify({'error': 'invalid_token', 'description': 'Access token is missing or invalid'}), 401
    access_token = access_token.split(' ')[1]
    try:
        #decrpyt refresh token using pt server private key:
        access_token = base64.b64decode(access_token)
        access_token = ptserver_private_key.decrypt(
            access_token,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        ).decode('utf-8')
        # Decode and verify the access token
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        # Check expiration time
        if 'exp' in payload and payload['exp'] < int(time.time()):
            return jsonify({'error': 'invalid_token', 'description': 'Access token has expired'}), 401
        hash_id = request.args.get('hash_id')
        if not hash_id:
            return jsonify({'error': 'missing_parameter', 'description': 'Missing hash_id parameter'}), 400
        key = load_key()
        decrypted_data = decrypt_file('patients.xlsx.encrypted', key)
        patient_data = get_patient_data(hash_id, decrypted_data)
        if patient_data:
            serialized_data = msgpack.packb(patient_data)
            encrypted_data = user_public_key.encrypt(
                serialized_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')
            return jsonify(encrypted_data)
        else:
            return jsonify({'error': 'not_found', 'description': 'Patient record not found'}), 404
    except jwt.ExpiredSignatureError:
        # Token has expired
        return jsonify({'error': 'invalid_token', 'description': 'Access token has expired'}), 401
    except jwt.InvalidTokenError:
        # Token is invalid
        return jsonify({'error': 'invalid_token', 'description': 'Access token is invalid'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
