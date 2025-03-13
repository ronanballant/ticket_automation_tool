# from azure.identity import AzureCliCredential
# from azure.keyvault.secrets import SecretClient

# from config import secops_vault


# class KeyLoader:
#     def __init__(self, cert_path, key_path) -> None:
#         self.cert_path = cert_path
#         self.key_path = key_path

#     def get_loaded_keys(self):
#         with open(self.cert_load_path, "r") as f:
#             cert = f.readlines()

#         with open(self.cert_path, "w") as f:
#             for line in cert:
#                 f.write(line.replace("\\n", "\n").replace("\n ", "\n"))

#         with open(self.key_load_path, "r") as f:
#             key = f.readlines()

#         with open(self.key_path, "w") as f:
#             for line in key:
#                 f.write(line.replace("\\n", "\n").replace("\n ", "\n"))

#     def get_az_keys(self):
#         cert = self.get_az_secret.get_az_secret(self.cert_name)
#         with open(self.cert_path, "w") as f:
#             f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
#         key = self.get_az_secret.get_az_secret(key_name)
#         self.key_path = key_path
#         with open(self.key_path, "w") as f:
#             f.write(key.replace("\\n", "\n").replace("\n ", "\n"))

#     def get_az_secret(self, secret_name):
#         # Set the URL for your Key Vault
#         vault_url = secops_vault

#         try:
#             # Create an instance of the DefaultAzureCredential class
#             credential = AzureCliCredential()
#         except Exception as e:
#             print(f"Error creating Azure CLI credential: {e}")
#             print("Please run 'az login' to set up an account.")
#             return None

#         # Create an instance of the SecretClient class, which will be used to access secrets
#         client = SecretClient(vault_url=vault_url, credential=credential)

#         try:
#             # Get the value of a secret by its name
#             secret_value = client.get_secret(secret_name).value
#             return secret_value
#         except Exception as e:
#             print(f"Error retrieving secret: {e}")
#             return None