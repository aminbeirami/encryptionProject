from Crypto import Random
import random
import string
from Crypto.PublicKey import RSA
import base64

class RSAEncryption():

	def generate_keys(self):
		random_generator = Random.new().read
		key = RSA.generate(1024,random_generator)
		privateKey = key.exportKey()
		publicKey = key.publickey().exportKey()
		return publicKey, privateKey

	def encrypt(self,message,publicKey):
		publicKeyObject = RSA.importKey(publicKey)
		randomParameter = random.choice(string.ascii_uppercase)
		encryptedMessage = publicKeyObject.encrypt(message.encode('utf-8'),randomParameter)[0]
		encodedEncryptedMessage = base64.b64encode(encryptedMessage)
		return encodedEncryptedMessage

	def decrypt(self,encodedMessage, privateKey):
		privateKeyObject = RSA.importKey(privateKey)
		decodedMessage = base64.b64decode(encodedMessage)
		decryptedMessage = privateKeyObject.decrypt(decodedMessage)
		return decryptedMessage