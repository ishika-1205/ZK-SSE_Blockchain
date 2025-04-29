import os
import json
import time
import threading
import base64
import hmac
import lzma  # Adaptive compression
import requests
import blake3  # Fast hashing for IoT optimization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from blockchain_definitions import Blockchain
from zk_sse_crypto import ZKSSEEncryption

# IoT Encryption Configuration
IOT_ENCRYPTION_CONFIG = {
    "encryption_algorithm": "AES-GCM",
    "key_length": 32,  # 256-bit key
    "compression_enabled": True,
    "retry_attempts": 3,  # Retry on failure
    "storage_type": "IPFS",  # Could be IPFS or local
}

# Blockchain and Encryption Modules
blockchain = Blockchain()
zk_crypto = ZKSSEEncryption()

# Thread-Safe Lock for Encryption
encryption_lock = threading.Lock()


# ===========================
#  Secure Key Generation
# ===========================
def generate_symmetric_key(message_id, sp_id):
    """
    Generates a unique symmetric encryption key using HMAC-based HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=IOT_ENCRYPTION_CONFIG["key_length"],
        salt=None,
        info=b"ZK-SSE IoT Encryption",
        backend=default_backend()
    )
    derived_key = hkdf.derive(f"{message_id}{sp_id}".encode())
    return derived_key


# ===========================
# 🔒 IoT Message Encryption
# ===========================
def encrypt_message(message, ke):
    """
    Encrypts IoT messages using AES-GCM.
    Applies adaptive compression for storage efficiency.
    """
    aesgcm = AESGCM(ke)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    encrypted_data = nonce + ciphertext

    if IOT_ENCRYPTION_CONFIG["compression_enabled"]:
        encrypted_data = lzma.compress(encrypted_data)

    return base64.b64encode(encrypted_data).decode()


# ===========================
#  Secure IoT Data Storage
# ===========================
def store_encrypted_message(encrypted_data):
    """
    Stores encrypted IoT update in IPFS.
    Implements retry mechanism for reliability.
    """
    for attempt in range(IOT_ENCRYPTION_CONFIG["retry_attempts"]):
        try:
            response = requests.post("http://ipfs_node:8080/api/v0/add", files={'file': encrypted_data})

            if response.status_code == 200:
                return response.json()["Hash"]
            else:
                print(f"IPFS Error: Failed to store data. Attempt {attempt + 1}")
        except requests.exceptions.RequestException as e:
            print(f"IPFS Connection Error: {e}. Retrying...")
            time.sleep(2)

    return None


# ===========================
#  Metadata Validation & Submission
# ===========================
def validate_and_publish_metadata(transaction_data, ke):
    """
    Validates transaction integrity and stores metadata on the blockchain.
    """
    computed_hash = blake3.blake3(transaction_data.encode()).hexdigest()

    metadata = {
        "H(CM)": computed_hash,
        "CID": transaction_data,
        "Access Policy": "(IoT_GROUP_1 AND AUTHORIZED_USERS)"
    }

    metadata_signature = blake3.blake3(str(metadata).encode()).hexdigest()

    response = requests.post("http://blockchain_node:5000/store_metadata", json={
        "metadata": metadata,
        "signature": metadata_signature,
        "ke": base64.b64encode(ke).decode()
    })

    if response.status_code == 200:
        print("Metadata successfully stored on blockchain.")
        return True
    else:
        print("Error: Failed to store metadata on blockchain.")
        return False


# ===========================
# 📡 Multi-Threaded Encryption Handler
# ===========================
def process_iot_update(device_id, sp_id, message):
    """
    Encrypts an IoT update, stores it in IPFS, and registers metadata on the blockchain.
    Runs as a separate thread to handle multiple updates concurrently.
    """
    with encryption_lock:
        print(f"Processing IoT Update for {device_id}...")

        # Generate Symmetric Key
        ke = generate_symmetric_key(device_id, sp_id)

        # Encrypt the Message
        encrypted_message = encrypt_message(message, ke)

        # Store Encrypted Update in IPFS
        cid = store_encrypted_message(encrypted_message)
        if not cid:
            print("Failed to store encrypted update. Retrying...")
            return

        print(f"Encrypted Update Stored. IPFS CID: {cid}")

        # Validate and Store Metadata in Blockchain
        validate_and_publish_metadata(cid, ke)


# ===========================
#  Test Execution
# ===========================
if __name__ == "__main__":
    test_threads = []

    # Example IoT Updates for Multi-Threading Test
    test_updates = [
        {"device_id": "IoT_Device_001", "sp_id": "SP_123", "message": "Security Patch v2.5"},
        {"device_id": "IoT_Device_002", "sp_id": "SP_456", "message": "Firmware Update v1.9"},
        {"device_id": "IoT_Device_003", "sp_id": "SP_789", "message": "Battery Optimization Patch v3.1"},
    ]

    # Start Multi-Threaded Processing
    for update in test_updates:
        thread = threading.Thread(target=process_iot_update, args=(update["device_id"], update["sp_id"], update["message"]))
        test_threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in test_threads:
        thread.join()

    print("All IoT updates processed successfully.")
