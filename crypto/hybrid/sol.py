import os
import base64
import requests
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import random


IP = ""
PORT = 0


class SessionManager:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session_key = None

    def request_session_parameters(self):
        try:
            response = requests.post(f'{self.base_url}/api/request-session-parameters')
            response.raise_for_status()
            params = response.json()
            g = int(params['g'], 16)
            p = int(params['p'], 16)
            return g, p
        except requests.RequestException as e:
            raise ConnectionError("Failed to fetch session parameters") from e

    def init_session(self, g, p):
        client_private = random.randint(2, p - 2)
        client_public = pow(g, client_private, p)

        try:
            response = requests.post(f'{self.base_url}/api/init-session', json={'client_public_key': client_public})
            response.raise_for_status()
            result = response.json()
            if result['status_code'] == 200:
                server_public_key = int(result['server_public_key'], 16)
                session_key = pow(server_public_key, client_private, p)
                self.session_key = sha256(str(session_key).encode()).digest()
            else:
                raise ValueError(result.get('error', 'Session initialization failed'))
        except requests.RequestException as e:
            raise ConnectionError("Failed to initialize session") from e

    def request_challenge(self):
        try:
            response = requests.post(f'{self.base_url}/api/request-challenge')
            response.raise_for_status()
            return response.json()['encrypted_challenge']
        except requests.RequestException as e:
            raise ConnectionError("Failed to request challenge") from e

    def decrypt_challenge(self, encrypted_challenge):
        decoded_challenge = base64.b64decode(encrypted_challenge)
        iv, encrypted_data = decoded_challenge[:16], decoded_challenge[16:]
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), 16)

    def send_flag_request(self, challenge_hash):
        action = 'flag'
        iv = os.urandom(16)
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        encrypted_packet = iv + cipher.encrypt(pad(action.encode(), 16))
        encrypted_packet_b64 = base64.b64encode(encrypted_packet).decode()

        try:
            response = requests.post(f'{self.base_url}/api/dashboard', json={
                'challenge': challenge_hash,
                'packet_data': encrypted_packet_b64
            })
            response.raise_for_status()
            return response.json()['packet_data']
        except requests.RequestException as e:
            raise ConnectionError("Failed to send flag request") from e

    def decrypt_flag(self, encrypted_flag_data):
        flag_packet = base64.b64decode(encrypted_flag_data)
        iv, encrypted_flag = flag_packet[:16], flag_packet[16:]
        cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_flag), 16).decode()


def main():
    session_manager = SessionManager(f'http://{IP}:{PORT}')
    
    try:
        g, p = session_manager.request_session_parameters()

        session_manager.init_session(g, p)

        encrypted_challenge = session_manager.request_challenge()
        challenge = session_manager.decrypt_challenge(encrypted_challenge)
        challenge_hash = sha256(challenge).hexdigest()

        encrypted_flag_data = session_manager.send_flag_request(challenge_hash)
        flag = session_manager.decrypt_flag(encrypted_flag_data)

        print("Flag:", flag)
    except Exception as e:
        print("An error occurred:", e)


main()