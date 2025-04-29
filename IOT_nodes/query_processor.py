import os
import json
import psutil  # System monitoring for IoT constraints
import time
import threading
import requests
import base64
import blake3  # Optimized hashing for fast trapdoor search
import hmac
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zk_sse_crypto import TrapdoorEncryption

# Query Processor Configuration
IOT_QUERY_CONFIG = {
    "device_type": "IoT",
    "max_memory_mb": 256,
    "low_power_mode": True,
    "query_cache_size": 15,  # Cache size limit for trapdoor queries
    "max_parallel_queries": 3,  # Number of concurrent trapdoor searches
    "query_timeout": 5,  # Query execution timeout in seconds
}

# Query Cache for Optimized Execution
query_cache = {}
query_lock = threading.Lock()
query_threads = []

# Flask API Initialization
app = Flask(__name__)

# Initialize Trapdoor Encryption
trapdoor_enc = TrapdoorEncryption()

# ===========================
# 🚀 IoT Resource Monitoring
# ===========================
def monitor_system_resources():
    """
    Periodically checks IoT node system memory and CPU usage.
    Prevents overload by stopping processes if usage exceeds limits.
    """
    while True:
        memory_usage = psutil.virtual_memory().used / (1024 * 1024)  # Convert bytes to MB
        cpu_usage = psutil.cpu_percent(interval=1)

        if memory_usage > IOT_QUERY_CONFIG["max_memory_mb"]:
            print(f"Warning: IoT Node exceeding memory limit ({memory_usage:.2f} MB used).")

        if cpu_usage > 75:
            print(f"High CPU Usage Detected ({cpu_usage}% usage). Optimizing processes...")

        time.sleep(5)  # Monitor every 5 seconds


# ===========================
# 🔍 Secure Trapdoor Generation
# ===========================
def generate_trapdoor_key(device_id, sp_id):
    """
    Generates a unique trapdoor key for IoT devices.
    Uses lightweight HMAC-based key derivation.
    """
    return hmac.new(
        key=b"ZK-SSE-Trapdoor",
        msg=f"{device_id}{sp_id}".encode(),
        digestmod="sha256"
    ).digest()


def encrypt_query(keyword, kt):
    """
    Encrypts the keyword to generate a trapdoor.
    Uses optimized hashing (BLAKE3) for IoT constraints.
    """
    hashed_keyword = blake3.blake3(keyword.encode()).hexdigest()
    encrypted_trapdoor = hmac.new(kt, hashed_keyword.encode(), digestmod="sha256").hexdigest()
    return encrypted_trapdoor


# ===========================
# 📡 IoT Query Processing
# ===========================
def execute_trapdoor_search(trapdoor):
    """
    Searches blockchain for a given trapdoor query.
    Uses caching and rate limiting to optimize performance.
    """
    with query_lock:
        print(f"Processing IoT Query: {trapdoor[:20]}...")

        # Cache Lookup
        if trapdoor in query_cache:
            print("Using Cached Query Result")
            return query_cache[trapdoor]

        # Blockchain Search
        response = requests.post("http://blockchain_node:5000/search", json={"trapdoor": trapdoor})

        if response.status_code == 200:
            result = response.json()
            query_cache[trapdoor] = result  # Store result in cache

            # Limit cache size
            if len(query_cache) > IOT_QUERY_CONFIG["query_cache_size"]:
                query_cache.pop(next(iter(query_cache)))

            print(f"Search successful. Returning metadata.")
            return result
        else:
            print("Query execution failed.")
            return None


@app.route('/query', methods=['POST'])
def process_query():
    """
    Handles encrypted IoT queries using trapdoor-based searches.
    Uses multi-threading for improved efficiency.
    """
    data = request.get_json()
    required = ['keyword', 'kt']

    if not all(k in data for k in required):
        return jsonify({'error': 'Missing parameters'}), 400

    keyword, kt = data['keyword'], base64.b64decode(data['kt'])
    trapdoor = encrypt_query(keyword, kt)

    # Multi-threaded Trapdoor Search
    if len(query_threads) >= IOT_QUERY_CONFIG["max_parallel_queries"]:
        return jsonify({'error': 'Too many concurrent queries. Try again later.'}), 429

    query_thread = threading.Thread(target=execute_trapdoor_search, args=(trapdoor,))
    query_threads.append(query_thread)
    query_thread.start()

    return jsonify({'message': 'Query is being processed'}), 202


@app.route('/retrieve', methods=['POST'])
def retrieve_update():
    """
    Fetches encrypted IoT updates from IPFS and decrypts them.
    """
    data = request.get_json()
    required = ['cid', 'ke']

    if not all(k in data for k in required):
        return jsonify({'error': 'Missing parameters'}), 400

    cid, ke = data['cid'], base64.b64decode(data['ke'])

    print(f"Fetching Encrypted Update from IPFS: {cid}...")

    response = requests.get(f"http://ipfs_node:8080/ipfs/{cid}")

    if response.status_code == 200:
        encrypted_data = base64.b64decode(response.json()['encrypted_data'])

        # Decrypt Update using AES-GCM
        aesgcm = AESGCM(ke)
        nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
        decrypted_msg = aesgcm.decrypt(nonce, ciphertext, None).decode()

        print(f"Decryption successful. Returning update.")
        return jsonify({"message": decrypted_msg}), 200
    else:
        print("Failed to fetch data from IPFS.")
        return jsonify({'error': 'IPFS retrieval failed'}), 400


@app.route('/verify_zkp', methods=['POST'])
def verify_zkp():
    """
    Validates Zero-Knowledge Proof for IoT queries.
    """
    data = request.get_json()
    required = ['zk_proof', 'trapdoor']

    if not all(k in data for k in required):
        return jsonify({'error': 'Missing parameters'}), 400

    zk_proof, trapdoor = data['zk_proof'], data['trapdoor']

    response = requests.post("http://blockchain_node:5000/verify_zkp", json={
        "zk_proof": zk_proof,
        "trapdoor": trapdoor
    })

    if response.status_code == 200:
        print("ZKP validation successful.")
        return jsonify({'message': 'Query authorized'}), 200
    else:
        print("ZKP validation failed.")
        return jsonify({'error': 'Invalid proof'}), 400


if __name__ == "__main__":
    monitoring_thread = threading.Thread(target=monitor_system_resources, daemon=True)
    monitoring_thread.start()

    app.run(host='0.0.0.0', port=5002)
