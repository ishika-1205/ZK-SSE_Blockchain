import os
import requests
import base64
import time
import lzma  # Compression for optimized IoT storage
import blake3  # Faster hashing for IoT constraints
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Lightweight encryption

# IPFS Configuration
IPFS_CONFIG = {
    "api_url": "http://ipfs_node:8080/api/v0/",
    "max_retries": 3,  # Retries for network failures
    "request_timeout": 5  # Time in seconds before retrying
}

class IPFSIntegration:
    def __init__(self):
        """Initializes IPFS connection settings."""
        self.api_url = IPFS_CONFIG["api_url"]

    def store_encrypted_data(self, encrypted_data):
        """
        Stores encrypted IoT data in IPFS and returns the CID.
        Applies compression before storing to minimize storage overhead.
        """
        compressed_data = lzma.compress(encrypted_data.encode())

        for attempt in range(IPFS_CONFIG["max_retries"]):
            try:
                response = requests.post(
                    f"{self.api_url}add", files={'file': compressed_data}, timeout=IPFS_CONFIG["request_timeout"]
                )

                if response.status_code == 200:
                    return response.json()["Hash"]
                else:
                    print(f"IPFS Error: Failed to store data. Attempt {attempt + 1}")
            except requests.exceptions.RequestException as e:
                print(f"IPFS Connection Error: {e}. Retrying...")
                time.sleep(2)

        return None

    def fetch_encrypted_data(self, cid):
        """
        Retrieves encrypted IoT data from IPFS using its CID.
        """
        for attempt in range(IPFS_CONFIG["max_retries"]):
            try:
                response = requests.get(f"{self.api_url}cat?arg={cid}", timeout=IPFS_CONFIG["request_timeout"])

                if response.status_code == 200:
                    compressed_data = response.content
                    return lzma.decompress(compressed_data).decode()
                else:
                    print(f"IPFS Error: Failed to retrieve data. Attempt {attempt + 1}")
            except requests.exceptions.RequestException as e:
                print(f"IPFS Connection Error: {e}. Retrying...")
                time.sleep(2)

        return None

    def verify_data_integrity(self, received_data, expected_hash):
        """
        Verifies the integrity of retrieved data using BLAKE3 hash comparison.
        """
        computed_hash = blake3.blake3(received_data.encode()).hexdigest()
        return computed_hash == expected_hash

    def decrypt_data(self, encrypted_data, ke):
        """
        Decrypts IoT update data retrieved from IPFS using AES-GCM.
        """
        try:
            aesgcm = AESGCM(ke)
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            nonce, ciphertext = encrypted_data_bytes[:12], encrypted_data_bytes[12:]
            return aesgcm.decrypt(nonce, ciphertext, None).decode()
        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

# Example Usage
if __name__ == "__main__":
    ipfs = IPFSIntegration()
    
    # Simulated IoT Data
    sample_data = "IoT Security Update v4.2"
    encryption_key = os.urandom(32)  # 256-bit key

    # Encrypt Data
    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)
    encrypted_sample_data = aesgcm.encrypt(nonce, sample_data.encode(), None)
    encrypted_data = base64.b64encode(nonce + encrypted_sample_data).decode()

    # Store Data in IPFS
    cid = ipfs.store_encrypted_data(encrypted_data)
    if cid:
        print(f"Data stored successfully in IPFS. CID: {cid}")

    # Retrieve Data from IPFS
    retrieved_encrypted_data = ipfs.fetch_encrypted_data(cid)
    if retrieved_encrypted_data:
        print("Successfully retrieved encrypted update from IPFS.")

        # Verify Data Integrity
        if ipfs.verify_data_integrity(retrieved_encrypted_data, blake3.blake3(encrypted_data.encode()).hexdigest()):
            print("Data integrity verified.")

            # Decrypt Data
            decrypted_message = ipfs.decrypt_data(retrieved_encrypted_data, encryption_key)
            if decrypted_message:
                print(f"Decrypted IoT Update: {decrypted_message}")
            else:
                print("Failed to decrypt IoT update.")
        else:
            print("Data integrity check failed.")
    else:
        print("Failed to retrieve data from IPFS.")
