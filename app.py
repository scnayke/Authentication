from flask import Flask, request, jsonify
import json
import random
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from generate_keys import generate_rsa_keys

generate_rsa_keys()

app = Flask(__name__)

# Simulated CIDR database with unique IDs and OTPs
cidr_db = {
    "1234567890": {"otp": "111222"},  # Unique ID 1 with OTP 111222
    "9876543210": {"otp": "333444"}   # Unique ID 2 with OTP 333444
}

# Load RSA public and private keys for CIDR
with open("keys/cidr_private.pem", "rb") as f:
    cidr_private_key = RSA.import_key(f.read())

with open("keys/cidr_public.pem", "rb") as f:
    cidr_public_key = RSA.import_key(f.read())

### --- HELPER FUNCTIONS --- ###
# Encrypt AES session key using RSA (CIDR public key)
def rsa_encrypt_session_key(session_key):
    cipher_rsa = PKCS1_OAEP.new(cidr_public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    return encrypted_session_key

# Decrypt AES session key using RSA (CIDR private key)
def rsa_decrypt_session_key(encrypted_session_key):
    cipher_rsa = PKCS1_OAEP.new(cidr_private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    return session_key

# AES Encrypt PID data
def aes_encrypt_data(data, session_key):
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode(), AES.block_size))
    return base64.b64encode(ciphertext), base64.b64encode(cipher.nonce)

# AES Decrypt PID data
def aes_decrypt_data(ciphertext, nonce, session_key):
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=base64.b64decode(nonce))
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return plaintext.decode()

# HMAC-SHA256 to ensure data integrity
def create_hmac(data, session_key):
    h = HMAC.new(session_key, digestmod=SHA256)
    h.update(data.encode())
    return base64.b64encode(h.digest())

def verify_hmac(data, received_hmac, session_key):
    h = HMAC.new(session_key, digestmod=SHA256)
    h.update(data.encode())
    try:
        h.verify(base64.b64decode(received_hmac))
        return True
    except ValueError:
        return False

### --- AUA (Client) --- ###
@app.route('/aua/authenticate', methods=['POST'])
def aua_authenticate():
    data = request.json
    unique_id = data.get('id')
    otp = data.get('otp')
    
    if unique_id in cidr_db:
        # Generate AES session key
        session_key = get_random_bytes(32)  # AES-256 key

        # Encrypt the session key with CIDR's public key
        encrypted_session_key = rsa_encrypt_session_key(session_key)
        
        # Encrypt PID data (OTP in this case)
        encrypted_data, nonce = aes_encrypt_data(otp, session_key)
        
        # Create HMAC for integrity
        hmac = create_hmac(otp, session_key)

        # Send encrypted data to ASA
        response = {
            "id": unique_id,
            "encrypted_data": encrypted_data.decode(),
            "nonce": nonce.decode(),
            "hmac": hmac.decode(),
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode()
        }
        return jsonify(response)
    return jsonify({"message": "User not found"}), 404

### --- ASA (Gateway) --- ###
@app.route('/asa/forward', methods=['POST'])
def asa_forward():
    data = request.json
    unique_id = data.get('id')
    encrypted_data = data.get('encrypted_data')
    nonce = data.get('nonce')
    hmac = data.get('hmac')
    encrypted_session_key = base64.b64decode(data.get('encrypted_session_key'))

    # Forward to CIDR for verification
    cidr_response = verify_with_cidr(unique_id, encrypted_data, nonce, hmac, encrypted_session_key)
    return jsonify(cidr_response)

### --- CIDR (Validation System) --- ###
def verify_with_cidr(unique_id, encrypted_data, nonce, hmac, encrypted_session_key):
    # Decrypt the AES session key using CIDR's private key
    session_key = rsa_decrypt_session_key(encrypted_session_key)

    # Decrypt the OTP (PID data) using the AES session key
    otp = aes_decrypt_data(encrypted_data, nonce, session_key)

    # Verify HMAC for integrity
    if verify_hmac(otp, hmac, session_key):
        # Check OTP validity
        if unique_id in cidr_db and cidr_db[unique_id]['otp'] == otp:
            return {"auth_status": "yes"}
        else:
            return {"auth_status": "no", "message": "OTP mismatch"}
    else:
        return {"auth_status": "no", "message": "HMAC verification failed"}

if __name__ == '__main__':
    app.run(debug=True)

