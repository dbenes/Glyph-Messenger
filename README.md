This is a prototype instant messenger application for clinicians, built with Python and designed for easy integration into patient record system APIs following the OAuth 2.0 protocol standard.

The main.py application sends a GET request to the Authentication Server for a valid access token, which can then be used to retrieve a list of contactable staff members from the Resource Server. Access tokens can also be used to call specific slices of patient data from the Patient Record Server into individual chats. Access tokens are forged with expiration timers, and the main.py will request fresh access tokens throughout its operation.

JSONS are encrypted using Public Key Infrastructure, with client JSON messages to servers being encrypted using a unique private key which is stored locally on the client device. Upon initial boot, the Glyph client requests the client’s username and password, which is encoded immediately as a SHA-256 hash. These two variables are used to generate a unique private and public key pair. 

It does this by concatenating the username and password together, which are encoded into a single byte stream. The Password-Based Key Derivation Function 2 (PBKDF2) with HMAC-SHA256 are then used to derive a Public Key from this input data, referred to as PBKDF2HMAC. 

A private key is then derived using RSA encryption on the newly created PBKDF2 as the input. This private key is then used to generate  a public key using the public_key() function in Python’s cryptography library. These RSA public and private keys are then stored locally as .pem files, with the filenames based on the unique client IDs.  
