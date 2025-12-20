from azure.identity import AzureCliCredential
from azure.keyvault.secrets import SecretClient

from config import SECOPS_VAULT


def get_az_secret(secret_name):
    # Set the URL for your Key Vault
    vault_url = SECOPS_VAULT

    try:
        # Create an instance of the DefaultAzureCredential class
        credential = AzureCliCredential()
    except Exception as e:
        print(f"Error creating Azure CLI credential: {e}")
        print("Please run 'az login' to set up an account.")
        return None

    # Create an instance of the SecretClient class, which will be used to access secrets
    client = SecretClient(vault_url=vault_url, credential=credential)

    try:
        # Get the value of a secret by its name
        secret_value = client.get_secret(secret_name).value
        return secret_value
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None
