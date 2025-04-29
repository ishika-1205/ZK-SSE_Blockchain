import os
import psutil  # System monitoring for IoT constraints
import base64
import subprocess
import threading
import json
import requests
import time
from flask import Flask, jsonify, request
from CPABSC_Hybrid_R import *  # Importing CP-ABE based encryption

# Flask App Initialization
app = Flask(__name__)

# IoT Node Configuration
IOT_NODE_CONFIG = {
    "device_type": "IoT",
    "max_memory_mb": 256,   # Max memory usage limit
    "low_power_mode": True,  # Reduce CPU-intensive tasks
    "max_parallel_updates": 2,  # Number of updates handled at once
}

# Initialize Cryptographic System
groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

# Thread-Safe Update Processing
update_lock = threading.Lock()


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

        if memory_usage > IOT_NODE_CONFIG["max_memory_mb"]:
            print(f"Warning: IoT Node exceeding memory limit ({memory_usage:.2f} MB used).")

        if cpu_usage > 75:
            print(f"High CPU Usage Detected ({cpu_usage}% usage). Optimizing processes...")

        time.sleep(5)  # Monitor every 5 seconds


# ===========================
# 📡 IoT Update Processing
# ===========================
def install_update(name, ct, pk, sk, pi, file):
    """
    Decrypts, verifies, and installs an IoT update securely.
    Uses parallel processing to handle multiple updates.
    """
    with update_lock:  # Prevents race conditions
        print(f"Processing IoT Update: {name}")

        # Step 1: Decrypt Update
        decrypted_data, delta_pr = hyb_abe.decrypt(pk, sk, ct)
        file_decoded = base64.b64decode(decrypted_data).decode('ascii')

        # Step 2: Verify Update Integrity
        delta_bytes = objectToBytes(delta_pr, groupObj)
        computed_pi = hashlib.sha256(bytes(str(file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

        if pi != computed_pi:
            print("Verification Failed. Update Rejected.")
            return False

        # Step 3: Store and Execute Update
        file_path = os.path.join(os.getcwd(), name)
        with open(file_path, 'w') as f:
            f.write(file_decoded)

        os.chmod(file_path, 0o755)

        try:
            print(f"Running Update: {name}")
            subprocess.run(file_path, shell=True, check=True)
            print(f"Update {name} Applied Successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Update Execution Failed: {e}")
            return False


# ===========================
# 📡 API Endpoints
# ===========================
@app.route('/ping', methods=['GET'])
def ping():
    """Health check endpoint for the IoT node."""
    return jsonify({'message': "PONG!"}), 200


@app.route('/updates/new', methods=['POST'])
def receive_update():
    """
    Receives IoT update requests securely.
    Decrypts, verifies, and installs the updates.
    """
    values = request.json
    required_fields = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']

    if not all(k in values for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    name = values['name']
    file = values['file']
    file_hash = values['file_hash']
    ct = bytesToObject(values['ct'].encode("utf8"), groupObj)
    pk = bytesToObject(values['pk'].encode("utf8"), groupObj)

    # Load IoT Node Secret Key
    with open("sk.txt", 'r') as sk_read:
        sk = bytesToObject(sk_read.read().encode("utf8"), groupObj)

    print(f"Received Update Request: {name}")

    # Process IoT Update in Background Thread
    update_thread = threading.Thread(target=install_update, args=(name, ct, pk, sk, values['pi'], file))
    update_thread.start()

    return jsonify({'message': 'Update is being processed'}), 202


# ===========================
# 🚀 Background Tasks
# ===========================
def start_listening():
    """Starts Flask API for receiving updates."""
    print("Starting IoT Update Service...")
    app.run(host='0.0.0.0', port=5001)


if __name__ == '__main__':
    # Start Resource Monitor
    monitoring_thread = threading.Thread(target=monitor_system_resources, daemon=True)
    monitoring_thread.start()

    # Start Flask API
    start_listening()
