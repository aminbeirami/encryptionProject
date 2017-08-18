from lib import mySQLCon as mc
from lib import keyGen as kg
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from lib.config import *
from random import randint
import os
import base64


CLOUDSQL_CONNECTION_NAME = os.environ.get('CLOUDSQL_CONNECTION_NAME')
CLOUDSQL_USER = os.environ.get('CLOUDSQL_USER')
CLOUDSQL_PASSWORD = os.environ.get('CLOUDSQL_PASSWORD')
CLOUDSQL_DATABASE = os.environ.get('CLOUDSQL_DATABASE') 

def connect_to_DB():
    if os.getenv('SERVER_SOFTWARE', '').startswith('Google App Engine/'):
        db = mc.DataBase(CLOUDSQL_CONNECTION_NAME,CLOUDSQL_USER,CLOUDSQL_PASSWORD,CLOUDSQL_DATABASE,'GCSQL')
    else:
        db = mc.DataBase(SERVER,USERNAME,PASSWORD,DATABASE,'LOCAL')
    return db

def save_user_pass(userData,db):
    userid = randint(0,100)
    sql = "INSERT INTO users (userid,username,password,isadmin) VALUES (%s,%s,%s,%s)"
    username = userData[0][1]
    password = generate_password_hash(userData[1][1])
    parameters = (userid, username, password, False)
    db.insert(sql, parameters)
    return userid, username

def save_pub_priv(userid,publickey,privatekey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO securekeys (keyid,userid,publickey,privatekey) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, userid, publickey, privatekey)
    db.insert(sql, parameters)

def save_pub_key(userid,username,publickey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO publickeys (keyid,username,publickey,userid) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, username, publickey, userid)
    db.insert (sql, parameters)

def hashing_and_save(user_list):
    keyGen = kg.RSAEncryption()
    publickey, privatekey = keyGen.generate_keys()
    db = connect_to_DB()
    userid, username = save_user_pass(user_list,db)
    save_pub_priv(userid,publickey,privatekey,db)
    save_pub_key(userid,username,publickey,db)
    db.commit()

def fetch_username_and_password(username,password):
    db = connect_to_DB()
    sql = "SELECT * FROM users WHERE username = %s"
    arguments = (username,)
    result = db.query(sql,arguments)
    if result:
        authentication = check_password_hash(result[0][2],password)
        if authentication:
            if result[0][3] == 1:
                isadmin = True
            else:
                isadmin = False
            return (True,isadmin)
        else:    
            return (False,False)
    else:
        return (False,False)

def fetch_users_public():
    db = connect_to_DB()
    sql = "SELECT username,publicKey,userid FROM publickeys"
    queryResult = db.query(sql,None)
    username = [x for x,y,z in queryResult]
    publickey = [y for x,y,z in queryResult]
    userid = [z for x,y,z in queryResult]
    publicKeyDict = dict(zip(username,publickey))
    userIdDict = dict(zip(username,userid))
    return publicKeyDict, userIdDict

def fetch_users_username():
    list_of_usernames = []
    publicDict = fetch_users_public()[0]
    for key in publicDict:
        list_of_usernames.append(key)
    return list_of_usernames

def sendMessage(rawMessage):
    message = rawMessage[0][1]
    user = rawMessage [1][1]
    publicDict = fetch_users_public()[0]
    publickey = publicDict[user]
    keyGen = kg.RSAEncryption()
    encryptedMessage = keyGen.encrypt(message,publickey)
    save_encrypted_message(encryptedMessage,user)

def save_encrypted_message(message,user):
    messageId = randint(0,100)
    db = connect_to_DB()
    sql = "INSERT INTO messages (mid,message,user) VALUES (%s,%s,%s)"
    parameters = (messageId,message,user)
    db.insert(sql,parameters)
    db.commit()

def get_privatekey(username):
    userInfo = fetch_users_public()[1]
    userid = userInfo[username]
    db = connect_to_DB()
    sql = "SELECT privatekey FROM securekeys WHERE userid = (%s)"
    parameters = (userid,)
    result = db.query(sql,parameters)
    return result[0][0]

def fetch_messages():
    db = connect_to_DB()
    sql = "SELECT message,user FROM messages"
    result = db.query(sql,None)
    return result

def is_decoded(amin):
    specialChars = '^[/][=]$'
    if any(ext in amin for ext in specialChars):
        return True
    else:
        return False

def receive_messages(username):
    decoded_message = []
    privatekey = get_privatekey(username)
    messagesList = fetch_messages()
    keyGen = kg.RSAEncryption()
    for elements in messagesList:
        decrypted = keyGen.decrypt(elements[0], privatekey)
        if is_decoded(decrypted):
            decoded_message.append([base64.b64encode(decrypted), elements[1]])
        else:
            decoded_message.append([decrypted, elements[1]])
    return decoded_message
