#Written By Amin Beirami
import os
#MySQL configuration

SERVER = '127.0.0.1'
USERNAME = "username"
PASSWORD = "password"
DATABASE = "database name"

#SecretKey is used to encrypt the session cookies

SECRET_KEY = os.urandom(24)