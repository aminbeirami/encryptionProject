import base64
from Crypto import Random
from Crypto.PublicKey import RSA
import random
import string


Random_generator = Random.new().read
key = RSA.generate(1024,Random_generator)
private = key.exportKey()
public = key.publickey().exportKey()

message = 'hi'
public_key_object = RSA.importKey(public)
random_phrase = 'M'
encrypted_message = public_key_object.encrypt(message,random_phrase)[0]


encoded_encrypted_message= base64.b64encode(encrypted_message)

encrypted_message2 = base64.b64decode(encoded_encrypted_message)
private_key_object = RSA.importKey(private)

decrypted_message = private_key_object.decrypt(encrypted_message2)

print decrypted_message
print private

randomParameter = random.choice(string.ascii_uppercase)
print randomParameter