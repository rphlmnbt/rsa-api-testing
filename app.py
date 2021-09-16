from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import binascii
from flask import Flask, request, jsonify
app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'This is my first API call!'

@app.route('/encrypt', methods=["POST"])
#Encryption
def encrypt():
    input_json = request.get_json(force=True)

    data = input_json['msg'].encode("utf-8")
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()
    return "Encryption Sucess"



#Signing the data
@app.route('/sign', methods=["POST"])
def sign():
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    h = SHA256.new(ciphertext)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

@app.route('/decrypt', methods=["POST"])
#Decryption
def decrypt():

    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))
    return "Decryption Success"

#Verifying digital signature
@app.route('/verify' , methods=["POST"])
def verify():
    signature=sign()
    file_in = open("encrypted_data.bin", "rb")

    public_key = RSA.import_key(open("receiver.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
    [ file_in.read(x) for x in (public_key.size_in_bytes(), 16, 16, -1) ]

    h = SHA256.new(ciphertext)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print ("The signature is valid.")
    except (ValueError, TypeError):
        print ("The signature is not valid.")

    return "Verify Sucess"

def main():
    #encrypting data
    keyPair,pubKey=rsakeys()
    msg=b'Hello World'
    encrypted=encrypt(pubKey,msg)

    #signing
    signature=sign(keyPair,encrypted)

    #verifying
    verify(pubKey,encrypted,signature)

    #decrypting
    decrypted=decrypt(keyPair,encrypted)





