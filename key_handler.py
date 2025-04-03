import base64
import os

import get_az_secret
from config import (asheik_cert_name, asheik_key_name, asheik_ssh_key_name,
                    gkochner_cert_name, gkochner_key_name,
                    gkochner_ssh_key_name, mcohen_cert_name, mcohen_key_name,
                    mcohen_ssh_key_name, rballant_cert_name, rballant_key_name,
                    rballant_ssh_key_name, tbelouso_cert_name,
                    tbelouso_key_name, tbelouso_ssh_key_name)


class KeyHandler:
    def __init__(self, logger, cert_path, key_path, ssh_key_path, analyst="rballant") -> None:
        self.analyst = "rballant"
        self.cert_path = cert_path
        self.key_path = key_path
        self.ssh_key_path = ssh_key_path
        self.logger = logger

    def remove_personal_keys(self):
        try:
            self.logger.info(f"Reomving personal keys")
            os.remove(self.cert_path)
            os.remove(self.key_path)
        except Exception as e:
            self.logger.error(f"Failed to remove personal keys: {e}")
    
    def remove_ssh_keys(self):
        try:
            self.logger.info("Removing SSH keys")
            os.remove(self.ssh_key_path)
        except Exception as e:
            self.logger.error(f"Failed to remove ssh keys: {e}")

    def decode_key(self, key):
        self.logger.info("Decoding Key")
        return base64.b64decode(key)

    def get_key_names(self):
        if self.analyst == "asheik":
            self.cert_name = asheik_cert_name
            self.key_name = asheik_key_name
            self.ssh_key_name = asheik_ssh_key_name
        if self.analyst == "gkochner":
            self.cert_name = gkochner_cert_name
            self.key_name = gkochner_key_name
            self.ssh_key_name = gkochner_ssh_key_name
        if self.analyst == "mcohen":
            self.cert_name = mcohen_cert_name
            self.key_name = mcohen_key_name
            self.ssh_key_name = mcohen_ssh_key_name
        if self.analyst == "tbelouso":
            self.cert_name = tbelouso_cert_name
            self.key_name = tbelouso_key_name
            self.ssh_key_name = tbelouso_ssh_key_name
        else:
            self.cert_name = rballant_cert_name
            self.key_name = rballant_key_name
            self.ssh_key_name = rballant_ssh_key_name

    def get_ssh_key(self):
        self.logger.info("Getting SSH key")
        try:
            encoded_ssh_key = get_az_secret.get_az_secret(self.ssh_key_name)
            ssh_key = self.decode_key(encoded_ssh_key).decode("utf-8")
            with open(self.ssh_key_path, "w") as f:
                f.write(ssh_key.replace("\\n", "\n").replace("\n ", "\n"))

            os.chmod(self.ssh_key_path, 0o600)
        except:
            encoded_ssh_key = get_az_secret.get_az_secret(rballant_ssh_key_name)
            ssh_key = self.decode_key(encoded_ssh_key).decode("utf-8")
            with open(self.ssh_key_path, "w") as f:
                f.write(ssh_key.replace("\\n", "\n").replace("\n ", "\n"))
            
            os.chmod(self.ssh_key_path, 0o600)

    def get_personal_keys(self):
        self.logger.info("Getting Personal keys")
        try:
            encoded_cert = get_az_secret.get_az_secret(self.cert_name)
            cert = self.decode_key(encoded_cert).decode("utf-8")
            with open(self.cert_path, "w") as f:
                f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
        
            encoded_key = get_az_secret.get_az_secret(self.key_name)
            key = self.decode_key(encoded_key).decode("utf-8")
            with open(self.key_path, "w") as f:
                f.write(key.replace("\\n", "\n").replace("\n ", "\n"))
        except:
            encoded_cert = get_az_secret.get_az_secret(rballant_cert_name)
            cert = self.decode_key(encoded_cert).decode("utf-8")
            with open(self.cert_path, "w") as f:
                f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
        
            encoded_key = get_az_secret.get_az_secret(rballant_key_name)
            key = self.decode_key(encoded_key).decode("utf-8")
            with open(self.key_path, "w") as f:
                f.write(key.replace("\\n", "\n").replace("\n ", "\n"))
