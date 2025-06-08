###############################################################################
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec
###############################################################################
from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    kdf_ck,
)
import socket


class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes):
        """
        The certificate authority DSA public key is used to
        verify the authenticity and integrity of certificates
        of other users (see handout and receive_certificate)
        """
        # Feel free to store data as needed in the objects below
        # and modify their structure as you see fit.
        self.ca_public_key = cert_authority_public_key
        self.conns = {}  # data for each active connection
        self.certs = {}  # certificates of other users



    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict
        """
        elgamal_keys = generate_eg()
        self.private_key = elgamal_keys["private"]
        self.public_key = elgamal_keys["public"]
        certificate = {"username": username, "public": self.public_key}
        self.certificate = certificate
        return certificate


    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: bytes

        Returns:
            None
        """
        if verify_with_ecdsa(self.ca_public_key, str(certificate), signature):
            self.certs[certificate["username"]] = certificate
        else:
            raise ValueError("Tampering detected!")

    




    def send_message(self, name: str, plaintext: str) -> tuple[dict, tuple[bytes, bytes]]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, tuple(bytes, bytes))
        """
        header = {}
        if name not in self.conns:
            
            self.conns[name] = {}
            self.conns[name]["their_public"] = self.certs[name]["public"]
            self.generate_new_session_keys(name)

            dh = compute_dh(self.conns[name]["private"], self.conns[name]["their_public"])
            iv = gen_random_salt()
            root_key, sending_key = hkdf(dh, iv, "test")
            self.conns[name]["root_key"] = root_key
            self.conns[name]["sending_key"] = sending_key
            self.conns[name]["their_public"] = self.certs[name]["public"]
            self.conns[name]["key_changed"] = False
            self.conns[name]["receiving_n_expected"] = 1
            self.conns[name]["n"] = 0
            self.conns[name]["pn"] = 0
            header["root_key"] = iv
            header["name"] = self.certificate["username"]
        
        if self.conns[name]["key_changed"]:
            self.conns[name]["pn"] = self.conns[name]["n"]
            self.conns[name]["n"] = 0
            self.conns[name]["key_changed"] = False


        message_key, sending_key = kdf_ck(self.conns[name]["sending_key"])
        self.conns[name]["sending_key"] = sending_key

        iv = gen_random_salt()
        ciphertext_info = encrypt_with_gcm(message_key, plaintext, iv)

        self.conns[name]["n"] += 1


        # header["root_key"] = self.conns[name]["root_key"]
        header["name"] = self.certificate["username"]
        header["iv"] = iv
        header["public"] = self.conns[name]["public"]
        header["n"] = self.conns[name]["n"]
        header["pn"] = self.conns[name]["pn"]
        ciphertext = ciphertext_info

        # print(f"{self.certificate['username']} sent to {name}:\n" + str(header) + f"\n expected n: {self.conns[name]['receiving_n_expected']}\n\n")

        return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, tuple(bytes, bytes))

        Returns:
            plaintext: str
        """

        header, ciphertext = message


        if name not in self.conns:
            self.conns[name] = {}
            self.conns[name]["private"] = self.private_key
            self.conns[name]["their_public"] = self.certs[name]["public"]
            self.conns[name]["key_changed"] = False
            self.conns[name]["receiving_n_expected"] = 1
            self.conns[name]["n"] = 0
            self.conns[name]["pn"] = 0
            self.conns[name]["root_key"] = header["iv"]

        
        is_public_key_changed = self.conns[name]["their_public"] != header["public"]


        if is_public_key_changed:
            dh = compute_dh(self.conns[name]["private"], header["public"])
            root_key, receiving_key = hkdf(dh, header["root_key"] if "root_key" in header else self.conns[name]["root_key"], "test")
            self.conns[name]["root_key"] = root_key
            self.conns[name]["receiving_key"] = receiving_key
            self.conns[name]["key_changed"] = True
            self.conns[name]["receiving_n_expected"] = 1

            self.generate_new_session_keys(name)

            dh = compute_dh(self.conns[name]["private"], header["public"])
            root_key, chain_key = hkdf(dh, root_key, "test")
            self.conns[name]["root_key"] = root_key 
            self.conns[name]["sending_key"] = chain_key
        else:
            self.conns[name]["key_changed"] = False

        self.conns[name]["their_public"] = header["public"]

        # print(f"header: {header['n']}/ conns: {self.conns[name]['receiving_n_expected']}\n")
        if header["n"] == self.conns[name]["receiving_n_expected"]:
            self.conns[name]["receiving_n_expected"] += 1
        else:
            raise Exception("Messages out of order")

        # print(f"{self.certificate['username']} received from {name}:\n" + str(header) + f"\n expected n: {self.conns[name]['receiving_n_expected']}\n\n")

        message_key, receiving_key = kdf_ck(self.conns[name]["receiving_key"])
        self.conns[name]["receiving_key"] = receiving_key

        plaintext = decrypt_with_gcm(message_key, ciphertext, header["iv"])

        
        return plaintext

    def generate_new_session_keys(self, name):
        conn_keys = generate_eg()
        self.conns[name]["public"] = conn_keys["public"]
        self.conns[name]["private"] = conn_keys["private"]


###################################
# Simulated IPsec Transport Layer #
###################################

STATIC_IPSEC_KEY = hmac_to_aes_key(b"session_psk", "ipsec")

def send_via_simulated_ipsec(dest_ip: str, dest_port: int, data: bytes):
    """
    Encrypts the data using AES-GCM with a static IPsec key and sends it over a socket.

    Inputs:
        dest_ip: str - IP address to send data to.
        dest_port: int - Port number to send data to.
        data: bytes - Raw byte data to encrypt and send.
    """
    iv = gen_random_salt()
    cipherText,tag = encrypt_with_gcm(STATIC_IPSEC_KEY,data.decode(),iv)
    payload = iv + tag + cipherText

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((dest_ip,dest_port))
        s.sendall(payload)

def receive_via_simulated_ipsec(bind_ip: str, bind_port: int) -> bytes:
    
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.bind((bind_ip,bind_port))
        s.listen(1)
        conn,_ = s.accept()
        with conn:
            data = b""
            while True:
                packet = conn.recv(4096)
                if not packet:
                    break
                data += packet

    iv = data[:16]
    tag = data[16:32]
    cipherText = data[32:]
    plainText = decrypt_with_gcm(STATIC_IPSEC_KEY,(cipherText,tag),iv,decode_bytes=False)
    return plainText
