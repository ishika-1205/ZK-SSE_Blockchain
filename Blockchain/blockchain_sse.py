# File: blockchain/blockchain_sse.py
import hashlib
import json
import time
import requests
import base64
import os
from urllib.parse import urlparse
from ipfs_integration import IPFSStorage
from zk_proof import ZeroKnowledgeProof
from cryptography.fernet import Fernet

class BlockchainSSE:
    """
    Implements Searchable Symmetric Encryption (SSE) integrated with blockchain
    for secure and privacy-preserving IoT message dissemination.
    """

    def __init__(self):
        """
        Initializes the Blockchain SSE system.
        """
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.ipfs = IPFSStorage()  # IPFS Off-Chain Storage
        self.zk_proof = ZeroKnowledgeProof()  # Zero-Knowledge Proof for Query Validation
        self.trapdoor_keys = {}  # Stores Device-specific Trapdoor Keys

        # Generate Blockchain Metadata Signing Keys (Ksign, Kverify)
        self.metadata_sign_key = hashlib.sha256(b"metadata_signing_key").hexdigest()
        self.metadata_verify_key = hashlib.sha256(b"metadata_verification_key").hexdigest()

        # Create the genesis block
        self.new_block(previous_hash="1", proof=100)

    def register_node(self, address):
        """
        Adds a new node to the blockchain network.
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("Invalid Node Address")

    def encrypt_keyword(self, keyword, device_id):
        """
        Encrypts a search keyword using the trapdoor key of the respective IoT device.
        """
        if device_id not in self.trapdoor_keys:
            self.trapdoor_keys[device_id] = Fernet.generate_key()
        cipher = Fernet(self.trapdoor_keys[device_id])
        return cipher.encrypt(keyword.encode()).decode()

    def generate_trapdoor(self, keyword, device_id):
        """
        Generates an encrypted trapdoor query for secure IoT message retrieval.
        """
        encrypted_keyword = self.encrypt_keyword(keyword, device_id)
        return encrypted_keyword

    def verify_trapdoor(self, encrypted_query, device_id):
        """
        Verifies if the trapdoor query is valid before granting access.
        """
        proof = self.zk_proof.generate_proof(device_id, encrypted_query)
        return self.zk_proof.verify_proof(proof)

    def encrypt_message(self, message, device_id):
        """
        Encrypts an IoT update before storing it in IPFS.
        """
        if device_id not in self.trapdoor_keys:
            self.trapdoor_keys[device_id] = Fernet.generate_key()
        cipher = Fernet(self.trapdoor_keys[device_id])
        return cipher.encrypt(message.encode()).decode()

    def new_transaction(self, device_id, message, keywords):
        """
        Creates a new encrypted transaction and stores metadata in the blockchain.
        """
        encrypted_message = self.encrypt_message(message, device_id)
        cid = self.ipfs.store_on_ipfs(encrypted_message)
        if not cid:
            raise ValueError("IPFS Storage Failed")

        # Compute Message Hash
        message_hash = hashlib.sha256(encrypted_message.encode()).hexdigest()

        # Create Searchable Index
        searchable_index = {kw: self.generate_trapdoor(kw, device_id) for kw in keywords}

        # Generate Metadata
        metadata = {
            "H(CM)": message_hash,
            "CID": cid,
            "Access Policy": f"Restricted to Device {device_id}",
            "Index": searchable_index
        }

        # Sign Metadata
        signature = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()

        transaction = {
            "Metadata": metadata,
            "Signature": signature
        }

        self.current_transactions.append(transaction)
        return self.last_block["index"] + 1

    def new_block(self, previous_hash, proof):
        """
        Creates a new block in the blockchain.
        """
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "transactions": self.current_transactions,
            "previous_hash": previous_hash,
            "proof": proof
        }

        self.current_transactions = []
        self.chain.append(block)
        return block

    def hash(self, block):
        """
        Creates a SHA-256 hash of a block.
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof-of-Work Algorithm:
        - Find a number 'proof' such that hash(last_proof, proof) contains 4 leading zeros
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        """
        Validates the proof of work.
        """
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def validate_transaction(self, transaction):
        """
        Validates a transaction before adding it to the blockchain.
        """
        metadata = transaction["Metadata"]
        computed_signature = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
        return computed_signature == transaction["Signature"]

    def process_query(self, encrypted_query, device_id):
        """
        Processes an encrypted trapdoor query for secure IoT message retrieval.
        """
        if not self.verify_trapdoor(encrypted_query, device_id):
            print("[❌] Unauthorized Query Detected!")
            return None

        # Search blockchain for matching searchable index
        for block in self.chain:
            for transaction in block["transactions"]:
                metadata = transaction["Metadata"]
                for kw, trapdoor in metadata["Index"].items():
                    if trapdoor == encrypted_query:
                        print(f"[✔] Match Found! Retrieving CID: {metadata['CID']}")
                        return self.ipfs.retrieve_from_ipfs(metadata["CID"])
        
        print("[❌] No Matching Record Found")
        return None

if __name__ == "__main__":
    blockchain = BlockchainSSE()

    # Simulated IoT Device ID
    device_id = "device_123"

    # IoT Message & Keywords
    iot_message = "Emergency firmware update required for security vulnerability."
    keywords = ["firmware", "update", "security", "patch"]

    # Create Transaction
    blockchain.new_transaction(device_id, iot_message, keywords)

    # Generate Trapdoor Query
    query_keyword = "security"
    trapdoor_query = blockchain.generate_trapdoor(query_keyword, device_id)

    # Process Secure Query
    retrieved_message = blockchain.process_query(trapdoor_query, device_id)

    # Compare Original and Retrieved Message
    if retrieved_message and retrieved_message == iot_message:
        print("[✔] Secure Query and Retrieval Successful!")
    else:
        print("[❌] Secure Query Failed!")
