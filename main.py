from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import base64
import pyttsx3


plain_text_AESKey = "1234567890123456"
plain_text_3desKey = "my16bytepassword"
plain_text_RSAKey = "1048"

engine = pyttsx3.init()

# Caesar Cipher
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            char_code = ord(char) + shift
            if char.isupper():
                if char_code > ord('Z'):
                    char_code -= 26
                elif char_code < ord('A'):
                    char_code += 26
            elif char.islower():
                if char_code > ord('z'):
                    char_code -= 26
                elif char_code < ord('a'):
                    char_code += 26
            ciphertext += chr(char_code)
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    engine.say("Encryption and decryption using Caesar Cipher is completed.")
    engine.runAndWait()
    return caesar_encrypt(ciphertext, -shift)

# Triple DES
def des3_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode()

def des3_decrypt(ciphertext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext.encode())
    plaintext = cipher.decrypt(ciphertext)
    unpadded_plaintext = unpad(plaintext, DES3.block_size)
    engine.say("Encryption and decryption using 3 Data Encryption standard is completed.")
    engine.runAndWait()
    return unpadded_plaintext.decode()


# Advanced Encryption Standard (AES)
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext.encode())
    plaintext = cipher.decrypt(ciphertext)
    unpadded_plaintext = unpad(plaintext, AES.block_size)
    engine.say("Encryption and decryption using Advanced Encryption Standard is completed. ")
    engine.runAndWait()
    return unpadded_plaintext.decode()


# Rivest–Shamir–Adleman (RSA)
def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    engine.say("Encryption and decryption using Rivest–Shamir–Adleman is completed.")
    engine.runAndWait()
    return plaintext.decode()


# Advanced Encryption Standard (AES)
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext.encode())
    plaintext = cipher.decrypt(ciphertext)
    unpadded_plaintext = unpad(plaintext, AES.block_size)
    engine.say("Encryption and decryption using Advanced Encryption standard is completed.")
    engine.runAndWait()
    return unpadded_plaintext.decode()


# Main program
engine = pyttsx3.init()
while True:
    menu_text = "Please select an algorithm:"
    engine.say(menu_text)
    engine.runAndWait()
    print(menu_text)
    print("1. Caesar Cipher")
    print("2. Triple DES")
    print("3. Advanced Encryption Standard (AES)")
    print("4. Rivest–Shamir–Adleman (RSA)")
    choice = input("Enter your choice (1-4): ")

    if choice == "1":
        plaintext = input("Enter the plaintext: ")
        shift = int(input("Enter the shift: "))
        ciphertext = caesar_encrypt(plaintext, shift)
        print("Ciphertext:", ciphertext)
        engine.say("Ciphertext: " + ciphertext)
        decrypted_plaintext = caesar_decrypt(ciphertext, shift)
        print("Decrypted plaintext:", decrypted_plaintext)


    elif choice == "2":
       plaintext = input("Enter the plaintext: ")
       print(f"Use this key: {plain_text_3desKey}")
       key = input("Enter the key (must be 16, 24, or 32 bytes): ")
       ciphertext = des3_encrypt(plaintext, key)
       print("Ciphertext:", ciphertext)
       decrypted_plaintext = des3_decrypt(ciphertext, key)
       print("Decrypted plaintext:", decrypted_plaintext)


    elif choice == "3":
        plaintext = input( "Enter the plaintext: ")
        print(f"Use this key: {plain_text_AESKey}")
        key = input( "Enter the key (must be 16, 24, or 32 bytes): ")

        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')

        # Create the cipher object and encrypt the plaintext
        cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

        # Print the encrypted ciphertext and tag
        print("Ciphertext (encrypted message):", ciphertext)
        print("Tag (for verifying message integrity):", tag)

        # Print the decrypted plaintext
        print("Plaintext (decrypted message):", plaintext_bytes.decode('utf-8'))



    elif choice == "4":
        plaintext = input("Enter the plaintext: ")
        print( f"Use this key: {plain_text_RSAKey}")
        key_size = int(input("Enter the key size (in bits): "))
        key = RSA.generate(key_size)
        public_key = key.publickey()
        private_key = key
        ciphertext = rsa_encrypt(plaintext, public_key)
        print("Ciphertext:", ciphertext)
        decrypted_plaintext = rsa_decrypt(ciphertext, private_key)
        print("Decrypted plaintext:", decrypted_plaintext)



