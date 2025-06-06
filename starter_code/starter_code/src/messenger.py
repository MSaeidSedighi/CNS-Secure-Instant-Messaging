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
            dh = compute_dh(self.private_key, self.certs[name]["public"])
            iv = gen_random_salt()
            root_key, sending_key = hkdf(dh, iv, "test")
            self.conns[name] = {"root_key": root_key, "sending_key": sending_key}
            self.conns[name]["public"] = self.certs[name]["public"]
            header["root_key"] = iv
            header["name"] = self.certificate["username"]

        message_key, sending_key = kdf_ck(self.conns[name]["sending_key"])
        self.conns[name]["sending_key"] = sending_key

        iv = gen_random_salt()
        ciphertext_info = encrypt_with_gcm(message_key, plaintext, iv)


        # header["root_key"] = self.conns[name]["root_key"]
        header["name"] = self.certificate["username"]
        header["iv"] = iv
        header["public"] = self.public_key
        ciphertext = ciphertext_info
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
        is_public_key_changed = self.certs[name]["public"] != header["public"]


        if is_public_key_changed or name not in self.conns:
            dh = compute_dh(self.private_key, header["public"])
            root_key, receiving_key = hkdf(dh, header["root_key"] if "root_key" in header else self.conns[name]["root_key"], "test")
            self.conns[name] = {"root_key": root_key, "receiving_key": receiving_key}

            _ = self.generate_certificate(self.certificate["username"])

            dh = compute_dh(self.private_key, header["public"])
            root_key, chain_key = hkdf(dh, root_key, "test")
            self.conns[name]["root_key"] = root_key 
            self.conns[name]["sending_key"] = chain_key

            self.certs[name]["public"] = header["public"]

        

        message_key, receiving_key = kdf_ck(self.conns[name]["receiving_key"])
        self.conns[name]["receiving_key"] = receiving_key


        plaintext = decrypt_with_gcm(message_key, ciphertext, header["iv"])

        
        return plaintext


###################################
# Simulated IPsec Transport Layer #
###################################

STATIC_IPSEC_KEY = hmac_to_aes_key(b"session_psk", "ipsec")

def send_via_simulated_ipsec(dest_ip: str, dest_port: int, data: bytes):
    iv = {}
    # TO DO

def receive_via_simulated_ipsec(bind_ip: str, bind_port: int) -> bytes:
    # TO DO
    plaintext = {}
    return plaintext
