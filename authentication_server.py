from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import jwt
import time
import base64

app = Flask(__name__) #Flask is used for all the servers, a framewokrk for handling web applications that use HTTP such as OAuth 2.0


authserver_private_key = rsa.generate_private_key( #generating the private key for the authentication server.
    public_exponent=65537,
    key_size=2048,
)
authserver_public_key = authserver_private_key.public_key() #generating a public key based on this private key.

with open('authserver_private_key.pem', 'wb') as f: #saving the private key to a lcoal .pem file
    # Serialize the private key
    authserver_private_key_bytes = authserver_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )
    f.write(authserver_private_key_bytes)
with open('authserver_public_key.pem', 'wb') as f: #saving the public key to a lcoal .pem file
    # Serialize the private key
    authserver_public_key_bytes = authserver_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(authserver_public_key_bytes)

print(authserver_private_key_bytes)
print(authserver_public_key_bytes)

authserver_public_key = base64.b64encode(authserver_public_key_bytes).decode('utf-8') #serialising the public key for easse of transmission.

# Load client credentials from file
def load_client_credentials(filename):
    with open(filename, 'r') as file:
        credentials = {}
        for line in file:
            parts = line.strip().split('=')
            if len(parts) == 2:
                key, value = parts
                credentials[key] = {'client_id': key, 'client_secret': value}
            else:
                print(f"Ignoring line: {line.strip()} as it does not contain valid data.")
        return credentials

CLIENTS = load_client_credentials('client_credentials.txt')


# In a real implementation, this should be stored securely and not hardcoded
SECRET_KEY = "f4b3b8e99f43d4565ed7724a54585bde06d604f10daea12555f3b9a0a9f20e8"

# Store access tokens in memory for simplicity (not suitable for production)
access_tokens = {}

# OAuth 2.0 token endpoint
@app.route('/oauth/token', methods=['POST'])
def token():
    data = request.json  # Assuming the request contains JSON data
    client_id = data.get('client_id') #retrieving input username
    client_secret = data.get('client_secret') #retrieving input secret
    grant_type = data.get('grant_type') #retrieving grant type, in this case "client_credentials"

    if not client_id or not client_secret: #invalid if required data not present in json data.
        return jsonify({'error': 'invalid_request', 'description': 'Invalid client credentials'}), 400

    if grant_type == 'client_credentials':
        if CLIENTS.get(client_id) and CLIENTS[client_id]['client_secret'] == client_secret: #checking to see if client_credentials are valid
            # Extract the Base64-encoded public key from the JSON data
            user_public_key_base64 = data.get('user_public_key')
            # Decode the Base64-encoded public key to obtain the binary representation
            user_public_key_bytes = base64.b64decode(user_public_key_base64)
            # Generate a unique access token
            access_token = generate_access_token(client_id)
            access_tokens[access_token] = {'client_id': client_id}
            # Encrypt the access token with the user's public key
            user_public_key = serialization.load_pem_public_key(user_public_key_bytes, backend=default_backend())
            encrypted_token = user_public_key.encrypt(
                access_token.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Convert the encrypted token to Base64 for transmission
            encrypted_token_base64 = base64.b64encode(encrypted_token).decode('utf-8')

            return jsonify({'access_token': encrypted_token_base64, 'authserver_public_key': authserver_public_key, 'token_type': 'bearer', 'expires_in': 60}), 200
        else:
            return jsonify({'error': 'invalid_client', 'description': 'Invalid client credentials'}), 401

    elif grant_type == 'refresh_token':
        refresh_token = data.get('refresh_token')
        user_public_key = data.get('user_public_key')
        user_public_key = base64.b64decode(user_public_key)
        user_public_key = serialization.load_pem_public_key(user_public_key, backend=default_backend())
        if refresh_token:
            #decrpyt refresh token using authserver private key:
            refresh_token = base64.b64decode(refresh_token)
            refresh_token = authserver_private_key.decrypt(
                refresh_token,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
            ).decode('utf-8')
            # Check if the refresh token is valid
            try:
                payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
                client_id = payload.get('client_id')
                if not client_id:
                    raise jwt.InvalidTokenError('Invalid refresh token payload')
                # Generate a new access token
                access_token = generate_access_token(client_id)
                encrypted_token = user_public_key.encrypt(
                access_token.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
                # Convert the encrypted token to Base64 for transmission
                encrypted_token_base64 = base64.b64encode(encrypted_token).decode('utf-8')
                return jsonify({'access_token': encrypted_token_base64, 'token_type': 'bearer', 'expires_in': 60}), 200
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'invalid_grant', 'description': 'Expired refresh token'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'invalid_grant', 'description': 'Invalid refresh token'}), 401
        else:
            return jsonify({'error': 'invalid_request', 'description': 'Refresh token is missing'}), 400

    else:
        return jsonify({'error': 'unsupported_grant_type', 'description': 'Unsupported grant type'}), 400


def generate_access_token(client_id): #function for forging access tokens
    # Set expiration time (1 minute from the current time)
    expiration_time = int(time.time()) + 60  # 60 seconds = 1 minute
    payload = {
        'client_id': client_id,
        'exp': expiration_time  # Include expiration time in the payload
    }
    # Generate the access token by signing the payload with the secret key
    access_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return access_token

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
