# ZK-SSE Blockchain for Secure IoT Update Dissemination

---

## Project Overview

ZK-SSE Chain is a secure, scalable, and decentralized blockchain-based targeted update dissemination framework for Internet-of-Things (IoT) devices.

The system leverages **Searchable Symmetric Encryption (SSE)** and **Zero-Knowledge Proofs (ZKPs)** to enable efficient trapdoor-based querying and secure metadata validation without requiring a centralized Trusted Authority.

By anchoring lightweight metadata on a **permissioned blockchain** and offloading encrypted content to an **IPFS distributed storage layer**, the system ensures:

- End-to-end security
- High scalability for large IoT networks
- Lightweight computational demands optimized for constrained IoT devices

---

## Core Features

- **Searchable Symmetric Encryption (SSE)** for secure, privacy-preserving keyword-based queries
- **Bulletproofs-based Zero-Knowledge Proofs (ZKPs)** for efficient and scalable query authorization
- **Permissioned Blockchain Ledger** for verifiable metadata anchoring
- **Off-chain Content Storage** using IPFS to prevent blockchain bloat
- **IoT Device Optimizations** including low-memory and low-power operational modes
- **Decentralized Access Control** without reliance on centralized authorities

---

## Project Structure

```bash
ZK-SSE_Blockchain/
├── Blockchain/           
├── Deployment/         
├── IOT_nodes/           
├── performance_analysis/ 
└── README.md           
```

---

## Pre-requisites

- Python 3.8 or above
- pip3 (Python Package Manager)

---

## System Installation

### Step 1: Install Python 3.8+

**On Ubuntu/Linux:**

```bash
sudo apt update
sudo apt install python3.8
sudo apt install python3-pip
```

**On macOS:**

```bash
brew install python@3.8
brew install pip3
```

**On Windows:**
- Download Python 3.8+ from the [official Python website](https://www.python.org/).
- Ensure to check "Add Python to PATH" during installation.

---

### Step 2: Verify Installation

```bash
python3 --version
pip3 --version
```

---

### Step 3: Install Required Python Libraries

```bash
pip3 install flask pycryptodome blake3 ipfshttpclient requests tqdm
```

---

## Why These Libraries?

| Library | Purpose |
|:---|:---|
| **Flask** | Enables lightweight API interactions and communication simulation between blockchain nodes and IoT devices |
| **PyCryptodome** | Provides cryptographic primitives including AES encryption required for securing firmware updates |
| **BLAKE3** | Ultra-fast and secure hashing during trapdoor and metadata generation |
| **IPFS HTTP Client** | Interface with IPFS decentralized storage |
| **Requests** | HTTP communication between blockchain nodes and APIs |
| **tqdm** | Progress bar utility for tracking blockchain synchronization and IPFS file uploads |

---

## Execution Instructions

After setting up the environment and installing dependencies,  
run the secure update dissemination workflow:

```bash
./build/bundle/zk-sse
```


---

## System Workflow

- Blockchain Node initializes and connects to permissioned network.
- IPFS Node handshake and metadata integrity check performed.
- Bulletproofs Zero-Knowledge Proof system bootstrapped.
- IoT Device Node launched with low-power optimizations.
- Secure firmware updates are encrypted with AES-GCM and stored in IPFS.
- Metadata (hashes, policies) anchored immutably on blockchain.
- IoT devices perform trapdoor-based secure keyword searches.
- Zero-Knowledge Proof validation ensures authorized access.
- Encrypted firmware is securely retrieved and decrypted.


---

## Technical Stack

| Component | Technology Used |
|:---|:---|
| Blockchain Layer | Custom Python Permissioned Blockchain |
| Cryptography | AES-GCM, ChaCha20-Poly1305, BLAKE3 |
| Secure Queries | Searchable Symmetric Encryption (SSE) |
| Authentication | Bulletproofs-based Zero-Knowledge Proofs |
| Storage | IPFS (InterPlanetary File System) |
| IoT Device Optimization | 256MB memory limit, low-power operational modes |

---


## Conclusion

The **ZK-SSE Chain** project delivers a decentralized, scalable, and secure framework for IoT firmware updates.

By combining blockchain ledger immutability, off-chain encrypted storage through IPFS, and bulletproof ZKP authorization mechanisms,  
the system ensures **scalability, privacy, and robust security** for next-generation IoT ecosystems.


---
